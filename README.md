# README

The `threats-scanner` is a middleware on top of ClamAV, exposing REST APIs for common threats detection and handling. Incoming requests are served in First-In First-Out (*FIFO*) order.

## Handling backpressure

A high volume of requests, resource constraints, or network congestion can result in increased latency or an outright system crash. This service handles backpressure through a rate limiter: up to `N` requests can be served concurrently, while excess requests wait for their turn.
