"use strict";

/**
 * Utility that updates an element's text with the time since some timestamp.
 */
class UpdateTimeCounter {
  constructor(elementId) {
    this.elementId = elementId;
    this.updateTs = Date.now();
    this.intervalId = null;
    this.reset();
  }

  reset() {
    this.updateTs = Date.now();
    if (this.intervalId != null) {
      clearInterval(this.intervalId);
    }
    this.intervalId = setInterval(this.update.bind(this), 1000);
    this.update();
  }

  update() {
    let seconds = Math.round((new Date() - this.updateTs) / 1000);
    if (seconds <= 3) {
      $(`#${this.elementId}`).text("just now");
    } else if (seconds < 60) {
      $(`#${this.elementId}`).text(`${seconds} seconds ago`);
    } else {
      const minutes = Math.floor(seconds / 60);
      seconds = seconds % 60;
      let s = "s";
      if (minutes == 1) s = "";
      $(`#${this.elementId}`).text(
        `${minutes} minute${s}, ${seconds} seconds ago`);
    }
  }
}
