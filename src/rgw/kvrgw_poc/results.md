# KVRGW FDB Perf tests results

Hey Gaby, I've ran some benchmarks for the tests we talked about. I did this by
creating a new test harness which handles spinning up multiple perf drivers
which call directly into `KvRgwServiceImpl` much like
`backend/src/perf_driver.cpp`. You can see all the code at
https://github.com/healthwaite/ceph/tree/KVRGW_POC-healthwaite-perf-clean.
Look in the `perf` directory.

## Cluster setup

### Nodes

5 identical bare-metal nodes (host1-host5), each running FoundationDB
directly on the host. The same nodes also run the perf workers.

| Resource | Per node |
|----------|----------|
| RAM      | 256 GiB (~252 GiB usable per FDB status) |
| CPU      | <TODO: CPU model / cores> |
| Disk     | <TODO: NVMe model, count and capacity> (one FDB process per disk, mounted at /diskN) |

### FDB cluster

FDB deployed with `profile=3`. Redundancy mode `triple`, single region,
coordinators on 5 nodes. Total 90 storage + 8 log + 10 stateless processes.

| Setting | Value |
|---------|-------|
| redundancy_mode | triple |
| storage_engine | ssd-redwood-1 |
| log_engine | ssd-2 |
| logs | 8 |
| commit_proxies | 3 |
| grv_proxies | 1 |
| resolvers | 2 |
| coordinators | 5 |
| tenant_mode | disabled |

Process layout per node:

| Process class | Count per node | Total | Memory limit | Cache memory |
|---------------|----------------|-------|--------------|--------------|
| storage       | 18             | 90    | 10 GiB       | 4 GiB        |
| transaction (log) | 2          | 10 (8 used as logs, 2 idle) | 8 GiB | default |
| stateless     | 2              | 10 (commit/grv proxies, resolvers, master, CC, DD, ratekeeper, ...) | default | default |

## Object naming format

<TODO> in

## What is measured

<TODO> what metrics are measured, where they are outputted

## The benchmarks

We run the following suite of benchmarks in order.

### Test0: Load 1 billion (00-load)

We use 32 workers each with 128 threads. Keys are split evenly across the 32 x
128 threads.

1. Create 10 buckets (with versioning disabled)
2. Load up 1B keys evenly across the 10 buckets
3. Verify: list all objects and check every one is accounted for

## Test1: PutObject (01-run-put-object)

We use 32 workers each with 128 threads. The benchmark runs for 12 hours.
Each thread continually writes new keys (i.e. does not overwrite). 

Verification: we use ListObjects to ensure all newly written keys are present.

## Test2: ListObjects single worker single thread (02-run-list-objects-single-thread)

We use a single worker with a single thread. The worker picks the first bucket
(rgwkv-0) and lists the objects in the bucket using a page size of 1000. The
test runs for 20 minutes. If the thread reaches the end of the range it goes
back to the start.

Verification: at the end of the test we do a final ListObjects verification
to ensure that all initially loaded 1 billion keys are present.

## Test3: ListObjects multi thread (03-run-list-objects)

We use 10 workers each with 16 threads. Each worker looks at a single bucket.
e.g. worker-0 -> bucket-0, worker1 -> worker1... We then split the key range
up into single character prefixes (70 in total for our character set) and
distribute the prefixes over our 16 threads. Each thread scans all object
keys in its prefix lists using a page size of 1000. When a thread gets to
the end of its prefix list it goes back to the start. We run the test for 20 minutes.

Verification: at the end of the test we do a final ListObjects verification
to ensure that all initially loaded 1 billion keys are present.

## Test4: PutObject Overwrite (04-run-put-object-overwrite)

We use 32 workers each with 128 threads. The benchmark runs for 12 hours.
We split the initially loaded keyset [0, 1B) into disjoint sequential ranges
over the threads. Each thread continually overwrites each key in the range
continuously for 12 hours. When it gets to the end of it's range it returns
to the start.

Verification: at the end of the test we verify that every key in the [0, 1B)
range is present. We actually use ListObjectVersions to ensure that the
PutObject actually overwrote the "null" version and didn't introduce a
version of the object.

## Test5: PutObject Overwrite Versioned (05-run-put-object-overwrite-versioned)

This test enables versioning on the bucket.

We use 32 workers each with 128 threads. The benchmark runs for 12 hours.
We pick a contiguous 1 million key in the intially loaded 1 billion objects.
We split the range across all of the workers and threads. Each thread then
Each thread takes a key contiguous slice of the initally loaded 1B objects
and overwrites them continuously.

Verifcation: we keep a count of how many times each object was overwriten.
We then do a ListObjectVersions over the key-range and check that each object
has the expected number of version. The check only counts versions whose
timestamp is at or after the benchmark start time.

## Test6: Delete Multi (06-run-delete-multi)

This test delete all of the initially loaded 1 billion keys. We use 32 workers
each with 16 threads. The [0, 1B) key range is sharded into disjoint ranges over
the threads. Each thread issues delete multi requests with a page size of 1000
for sequential keys. We issue non-versioned deletes. The tests finishes when all
keys have been deleted for we exceed 12 hours.

Verification: we run list objects over each threads deleted range and assert
the keys do not exist.
