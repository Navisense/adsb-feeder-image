"use strict";

/**
 * Utility to check whether the feeder is reachable.
 */
class FeederConnectivityChecker {
  constructor(
    hosts,
    onStatusUpdate,
    checkTimeout = 300 * 1000,
    recheckIntervals = [
      [1000, 200],
      [3000, 500],
      [Infinity, 3000],
    ]
  ) {
    this.stati = new Map(
      hosts.map((h) => [h, { status: null, checkStart: 0 }])
    );
    this.onStatusUpdate = onStatusUpdate;
    this.checkTimeout = checkTimeout;
    this.recheckIntervals = recheckIntervals;
    this.checkStart = 0;
    this.hasTimedOut = false;
  }

  /**
   * Set the hosts to check to the ones contained in the array.
   *
   * The status of hosts that already exist is not changed. Hosts that didn't
   * yet exist are added with an initial status. Hosts that are not in the array
   * are removed.
   */
  setHosts(hosts) {
    for (const host of hosts) {
      if (this.stati.has(host)) {
        continue;
      } else {
        this.stati.set(host, { status: null, checkStart: Date.now() });
      }
    }
    for (const host of this.stati.keys()) {
      if (!hosts.includes(host)) {
        this.stati.delete(host);
      }
    }
  }

  getStati() {
    return this.stati;
  }

  start() {
    if (this.checkStart) {
      // Was already started.
      return;
    }
    this.checkStart = Date.now();
    for (const status of this.stati.values()) {
      status.checkStart = this.checkStart;
    }
    this.sendCheckRequests();
  }

  sendCheckRequests() {
    for (const [host, previousStatus] of this.stati.entries()) {
      let req = new XMLHttpRequest();
      req.timeout = 1000;
      req.onload = this.maybeUpdateStatus(
        host,
        previousStatus.status,
        "success"
      );
      req.onerror = this.maybeUpdateStatus(
        host,
        previousStatus.status,
        "error"
      );
      req.ontimeout = this.maybeUpdateStatus(
        host,
        previousStatus.status,
        "timeout"
      );
      req.open("GET", `http://${host}/api/statusz`);
      req.send();
    }
    let recheckInterval = 1000;
    const timeSinceStart = Date.now() - this.checkStart;
    for (const [threshold, interval] of this.recheckIntervals) {
      if (timeSinceStart <= threshold) {
        recheckInterval = interval;
        break;
      }
    }
    if (!this.hasTimedOut) {
      setTimeout(this.sendCheckRequests.bind(this), recheckInterval);
    }
  }

  maybeUpdateStatus(host, previousStatus, status) {
    return (_) => {
      this.stati.get(host).status = status;
      this.hasTimedOut = Date.now() > this.checkStart + this.checkTimeout;
      if (this.hasTimedOut || status != previousStatus) {
        this.onStatusUpdate(this.stati, this.hasTimedOut);
      }
    };
  }
}
