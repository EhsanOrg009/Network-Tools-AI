import "@testing-library/jest-dom/vitest";

// jsdom has no native dialog lifecycle; browsers provide the top layer,
// keyboard focus confinement and restoration used by the shared component.
HTMLDialogElement.prototype.showModal = function () { this.setAttribute("open", ""); };
HTMLDialogElement.prototype.close = function () { this.removeAttribute("open"); };
