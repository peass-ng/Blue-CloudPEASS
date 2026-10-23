# Large inventory worker sizing

Public defaults remain collector 1 vCPU / 6 GiB and analyzer 0.5 vCPU / 4 GiB. These are starting sizes, not a capacity guarantee. Deployment configuration can select supported 2 vCPU Fargate tasks with 4–16 GiB in 1 GiB increments; collector minimum remains 6 GiB and analyzer minimum 4 GiB.

A real uncapped two-account audit collected more than 350,000 resources, then exceeded an 8 GiB collector during final processing. Cumulative checkpoint copy removal reduces allocation pressure without skipping any section publication. Large-estate qualification uses a 2 vCPU / 16 GiB collector and a 1 vCPU / 8 GiB analyzer while verifying completion; these measurements do not establish capacity for every estate.

CPU/memory overrides are validated both before variable generation and against saved task definitions. The reviewed source extension reconstructs the previous runtime-limit source exactly; historical source hashes are retained. Runtime cost estimates read the deployed stage sizes.

Supported sizes: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
