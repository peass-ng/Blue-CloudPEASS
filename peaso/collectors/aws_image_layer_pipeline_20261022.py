"""Two bounded layer transports; native SDK calls and source order stay serial."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from copy import copy
import threading

MAX_LAYER_DOWNLOADS = 2


def download_layers(reader, repo, descriptors, root, image_digest):
    """Join every transport before returning to its caller's scratch owner.

    Descriptor order is the image layer order. Each worker owns its ledger, while
    the original Reader owns SDK budgets and client construction under one lock.
    Explicit global caps or insufficient native SDK budgets keep serial admission.
    """
    from .aws_image_vulnerability_native_20261021 import MAX_CALLS
    count = len(descriptors)
    if (count < 2 or reader.requests.max_calls is not None
            or count > min(MAX_CALLS - reader.target_calls, reader.max_calls - reader.calls)):
        return [reader.blob(repo, desc, path=root / f'layer-{i}.blob', image_digest=image_digest)
                for i, desc in enumerate(descriptors)]

    stopped = threading.Event()
    sdk_lock = threading.Lock()
    ledgers = [[] for _ in descriptors]
    results = [None] * count

    def run(index):
        local = copy(reader)
        local.ledger = ledgers[index]
        def check():
            reader.check()
            if stopped.is_set():
                raise ValueError('image_layer_download_cancelled')
        def call(service, operation, **arguments):
            # Client creation and SDK calls use the original Reader. Only HTTP
            # body transfers overlap; no Boto3 Session is used concurrently.
            with sdk_lock:
                check()
                start = len(reader.ledger)
                try:
                    return reader.call(service, operation, **arguments)
                finally:
                    local.ledger.extend(reader.ledger[start:])
                    del reader.ledger[start:]
        local.check = check
        local.call = call
        check()
        return local.blob(repo, descriptors[index], path=root / f'layer-{index}.blob',
                          image_digest=image_digest)

    try:
        with ThreadPoolExecutor(max_workers=MAX_LAYER_DOWNLOADS,
                                thread_name_prefix='peaso-ecr-layer') as pool:
            pending = {}
            try:
                for i in range(min(count, MAX_LAYER_DOWNLOADS)):
                    pending[pool.submit(run, i)] = i
                next_index = len(pending)
                while pending:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    # Observe every finished error before submitting more work.
                    completed = [(future, pending[future], future.result())
                                 for future in sorted(done, key=pending.get)]
                    for future, index, path in completed:
                        del pending[future]
                        results[index] = path
                    for _ in completed:
                        if next_index < count:
                            pending[pool.submit(run, next_index)] = next_index
                            next_index += 1
            except BaseException:
                stopped.set()
                for future in pending:
                    future.cancel()
                raise
    finally:
        # Executor shutdown has joined all workers before the outer scratch is
        # removed, including when one worker fails or the job is cancelled.
        for ledger in ledgers:
            reader.ledger.extend(ledger)
    return results
