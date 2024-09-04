import { Controller } from "@hotwired/stimulus";
import { dispatchDialogOpen } from "./dialog";

// Assume globally only have ONE single dialog
const DIALOG_ID = "settings-dialog";
/**
 * Dispatch a custom event to set captcha dialog open
 */

export function dispatchSettingsDialogOpen() {
  dispatchDialogOpen(DIALOG_ID);
}

export class SettingsDialogController extends Controller {
  open = (_: Event) => {
    dispatchSettingsDialogOpen();
  };
}
