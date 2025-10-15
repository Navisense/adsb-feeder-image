"use strict";

/**
 * Utility that updates an element's text with the time since some timestamp.
 *
 * Takes an ID for a counter element, and one for a refresh button. Updates the
 * counter element once per second with a human-readable duration since the last
 * call to refresh() or to construction. During the first few seconds, that
 * string is "just now", and during this time the button is disabled.
 */
class UpdateTimeCounter {
  constructor(counterElementId, buttonElementId) {
    this.counterElementId = counterElementId;
    this.buttonElementId = buttonElementId;
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
      $(`#${this.buttonElementId}`).attr("disabled", "");
      $(`#${this.counterElementId}`).text("just now");
    } else {
      $(`#${this.buttonElementId}`).removeAttr("disabled");
      if (seconds < 60) {
        $(`#${this.counterElementId}`).text(`${seconds} seconds ago`);
      } else {
        const minutes = Math.floor(seconds / 60);
        seconds = seconds % 60;
        let s = "s";
        if (minutes == 1) s = "";
        $(`#${this.counterElementId}`).text(
          `${minutes} minute${s}, ${seconds} seconds ago`
        );
      }
    }
  }
}
