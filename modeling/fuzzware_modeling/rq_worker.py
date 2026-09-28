#!/usr/bin/env python
from rq import Connection, Worker
import redis
import argparse

# Import the libraries which we know the worker will need every time after its fork
import angr
import claripy
import archinfo

parser = argparse.ArgumentParser(description="Fuzzware modeling worker")
parser.add_argument('queues', nargs="+")
parser.add_argument('--burst', default=False, action='store_true', help="Run in burst mode?")
parser.add_argument('--port', default=6379, help="Connect to redis on the specified port.")
args = parser.parse_args()

redis_conn = redis.Redis(
    port=args.port,
    socket_connect_timeout=10,
    socket_timeout=500,
    socket_keepalive=True,
)

print(
    "Redis connection configuration:",
    redis_conn.connection_pool.connection_kwargs,
    flush=True,
)

with Connection(redis_conn):
#with Connection(redis.Redis(port=args.port)):
    qs = args.queues

    w = Worker(qs)

    w.work(burst=args.burst)
