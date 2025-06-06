package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/sync/errgroup"
)

// startFuzzCycles runs an infinite loop of fuzzing cycles. Each cycle consists
// of:
//  1. Cloning or pulling the Git repository specified in cfg.ProjectSrcPath.
//  2. Listing fuzz targets in the cloned repository.
//  3. Launching scheduler goroutines to execute all fuzz targets for a portion
//     of cfg.SyncFrequency.
//  4. Cleaning up the workspace (deleting cfg.ProjectDir, temporary artifacts,
//     etc.).
//
// The loop repeats until the parent context is canceled. Errors in cloning or
// target discovery are returned immediately
func startFuzzCycles(ctx context.Context, logger *slog.Logger, cfg *Config,
	cycleDuration time.Duration) {

	for {
		// 1. Clone or pull the repository.
		logger.Info("Syncing project repository", "repo_url",
			SanitizeURL(cfg.ProjectSrcPath), "local_path",
			cfg.ProjectDir)

		_, err := git.PlainCloneContext(
			ctx, cfg.ProjectDir, false, &git.CloneOptions{
				URL: cfg.ProjectSrcPath,
				// Temporary until the previous PR got merged
				ReferenceName: plumbing.NewBranchReferenceName(
					"fuzz-example"),
				SingleBranch: true,
				Depth:        1,
				// // Temporary until the previous PR got merged
			},
		)
		if err != nil {
			logger.Error("Failed to sync repository; aborting "+
				"scheduler", "error", err)

			// Perform workspace cleanup before exiting due to the
			// cloning error.
			cleanupWorkspace(logger, cfg)
			os.Exit(1)
		}

		// Download corpus from S3 bucket
		s3Client, err := createS3Client(ctx)
		if err != nil {
			logger.Error("Failed to create S3 client", "error", err)

			// Perform workspace cleanup before exiting due to the
			// corpus download error.
			cleanupWorkspace(logger, cfg)
			os.Exit(1)
		}

		corpusZipPath := cfg.CorpusDir + ".zip"
		empty, err := downloadObject(ctx, s3Client, cfg.S3BucketName,
			CorpusKey, corpusZipPath, logger)
		if err != nil {
			logger.Error("Download failed", "error", err)

			// Perform workspace cleanup before exiting due to the
			// corpus download error.
			cleanupWorkspace(logger, cfg)
			os.Exit(1)
		}

		if !empty {
			if err := unzip(corpusZipPath, cfg.CorpusDir,
				logger); err != nil {
				logger.Error("Unzip failed", "error", err)

				// Perform workspace cleanup before exiting due
				// to the corpus download error.
				cleanupWorkspace(logger, cfg)
				os.Exit(1)
			}
		}

		// 2. Discover fuzz targets.
		pkgTargets, totalTargets, err := listPkgsFuzzTargets(ctx,
			logger, cfg)
		if err != nil {
			logger.Error("Failed to list fuzz targets; aborting "+
				"scheduler", "error", err)

			// Perform workspace cleanup before exiting due to the
			// list fuzz targets error.
			cleanupWorkspace(logger, cfg)
			os.Exit(1)
		}

		if totalTargets == 0 {
			logger.Warn("No fuzz targets found; aborting " +
				"scheduler; please add some fuzz targets")
			cleanupWorkspace(logger, cfg)
			os.Exit(0)
		}

		// 3. Create a cycle sub-context for this fuzz iteration.
		schedulerCtx, cancelCycle := context.WithCancel(ctx)

		// Channel to check if the cycle is cancelled, before cleanup.
		doneChan := make(chan struct{})

		// Launch the fuzz worker scheduler as a goroutine.
		go scheduleFuzzing(schedulerCtx, logger, cfg,
			pkgTargets, totalTargets, doneChan)

		// 4. Wait for either:
		//    A) All workers finish early
		//    B) cycleDuration elapses
		//    C) Parent context cancellation
		select {
		case <-doneChan:
			// If all the workers stopped prematurely
			logger.Info("All workers completed early; cleaning " +
				"up cycle")

			// Upload the updated corpus back to cloud storage
			zipUploadCorpus(schedulerCtx, s3Client,
				cfg.S3BucketName, CorpusKey, cfg.CorpusDir,
				logger)

			// Cancel the current cycle.
			cancelCycle()
			cleanupWorkspace(logger, cfg)

		case <-time.After(cycleDuration):
			logger.Info("Cycle duration complete; initiating " +
				"cleanup.")

			// Upload the updated corpus back to cloud storage
			zipUploadCorpus(schedulerCtx, s3Client,
				cfg.S3BucketName, CorpusKey, cfg.CorpusDir,
				logger)

			// Cancel the current cycle.
			cancelCycle()

			// wait before the fuzzing worker is closed before
			// cleanup.
			<-doneChan
			cleanupWorkspace(logger, cfg)

		case <-ctx.Done():
			logger.Info("Shutdown initiated during fuzzing " +
				"cycle; performing final cleanup.")

			// Since the process is stopeed let's not upload this
			// corpus coz may be it got corupted.
			//
			// Overall application context canceled.
			cancelCycle()

			// wait before the fuzzing worker is closed before
			// cleanup.
			<-doneChan
			cleanupWorkspace(logger, cfg)

			return
		}
	}
}

// scheduleFuzzing enqueues all discovered fuzz targets into a task queue and
// spins up cfg.NumWorkers workers. Each worker runs until either:
//   - All tasks are completed.
//   - A worker returns an error (errgroup will cancel the others).
//   - The cycle context (ctx) is canceled.
//
// Returns an error if any worker fails.
func scheduleFuzzing(ctx context.Context, logger *slog.Logger, cfg *Config,
	pkgTargets map[string][]string, totalTargets int,
	doneChan chan struct{}) {

	defer close(doneChan)

	logger.Info("Starting fuzzing scheduler", "startTime", time.Now().
		Format(time.RFC1123))

	// Calculate the fuzzing time for each fuzz target.
	fuzzSeconds := CalculateFuzzSeconds(cfg.SyncFrequency,
		cfg.NumWorkers, totalTargets)
	if fuzzSeconds <= 0 {
		logger.Error("invalid fuzz duration", "duration", fuzzSeconds)

		// Perform workspace cleanup before exiting due to the fuzzing
		// error.
		cleanupWorkspace(logger, cfg)
		os.Exit(1)
	}
	perTargetTimeout := time.Duration(fuzzSeconds) * time.Second

	logger.Info("Per-target fuzz timeout calculated", "duration",
		perTargetTimeout)

	// Build a thread-safe task queue.
	taskQueue := NewTaskQueue()
	for pkgPath := range pkgTargets {
		for _, target := range pkgTargets[pkgPath] {
			taskQueue.Enqueue(Task{
				Package: pkgPath,
				Target:  target,
			})
		}
	}

	// Use an errgroup to cancel all workers if any single worker errors.
	g, goCtx := errgroup.WithContext(ctx)
	for i := 1; i <= cfg.NumWorkers; i++ {
		workerID := i // capture loop variable
		g.Go(func() error {
			return runWorker(workerID, goCtx, taskQueue,
				perTargetTimeout, logger, cfg)
		})
	}

	// Wait for all workers to finish or for the first error/cancellation.
	if err := g.Wait(); err != nil {
		logger.Error("Fuzzing process failed", "error", err)

		// Perform workspace cleanup before exiting due to the fuzzing
		// error.
		cleanupWorkspace(logger, cfg)
		os.Exit(1)
	}

	logger.Info("All fuzz targets processed successfully in this cycle")
}
