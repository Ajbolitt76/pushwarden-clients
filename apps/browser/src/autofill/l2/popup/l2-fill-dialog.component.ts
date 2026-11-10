import { ChangeDetectionStrategy, Component, inject, signal } from "@angular/core";
import { FormBuilder, ReactiveFormsModule } from "@angular/forms";

import { JslibModule } from "@bitwarden/angular/jslib.module";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import {
  AsyncActionsModule,
  ButtonModule,
  DIALOG_DATA,
  DialogModule,
  DialogRef,
  DialogService,
  FormFieldModule,
  IconButtonModule,
  TypographyModule,
} from "@bitwarden/components";

import { FillResult } from "../../types/fill-result";
import type { L2Unlock } from "../l2.service";

/** Outcome of one background fill attempt: a result, or the `L2ErrorCode` that stopped it. */
export type L2FillAttempt = { result: FillResult } | { error: string };

export interface L2FillDialogParams {
  host: string;
  fill: (unlock: L2Unlock) => Promise<L2FillAttempt>;
}

const ERROR_KEYS: Record<string, string> = {
  notPaired: "l2ErrorNotPaired",
  wrongPassword: "l2ErrorWrongPassword",
  noKeyItem: "l2ErrorNoKeyItem",
  multipleKeyItems: "l2ErrorMultipleKeyItems",
  hostNotAllowed: "l2ErrorHostNotAllowed",
  phoneDenied: "l2ErrorPhoneDenied",
  phoneRejected: "l2ErrorPhoneRejected",
  timeout: "l2ErrorTimeout",
  relayError: "l2ErrorRelay",
};

/**
 * Asks how to unlock an L2 item for one fill: approval on the paired phone, or the L2
 * password. Closes with the fill result, or `undefined` when cancelled.
 */
@Component({
  templateUrl: "l2-fill-dialog.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    JslibModule,
    AsyncActionsModule,
    ButtonModule,
    DialogModule,
    FormFieldModule,
    IconButtonModule,
    ReactiveFormsModule,
    TypographyModule,
  ],
})
export class L2FillDialogComponent {
  protected readonly params = inject<L2FillDialogParams>(DIALOG_DATA);
  private readonly dialogRef = inject(DialogRef<FillResult | undefined>);
  private readonly i18nService = inject(I18nService);

  protected readonly formGroup = inject(FormBuilder).group({ l2Password: [""] });
  protected readonly waitingForPhone = signal(false);
  protected readonly error = signal<string | null>(null);

  static open(dialogService: DialogService, data: L2FillDialogParams) {
    return dialogService.open<FillResult | undefined, L2FillDialogParams>(L2FillDialogComponent, {
      data,
    });
  }

  protected readonly approveOnPhone = async () => {
    this.waitingForPhone.set(true);
    try {
      await this.run({ mode: "phone" });
    } finally {
      this.waitingForPhone.set(false);
    }
  };

  protected readonly fillWithPassword = async () => {
    const password = this.formGroup.value.l2Password;
    if (!password) {
      return;
    }
    await this.run({ mode: "password", password });
    this.formGroup.reset();
  };

  private async run(unlock: L2Unlock) {
    this.error.set(null);
    const attempt = await this.params.fill(unlock);
    if ("result" in attempt) {
      void this.dialogRef.close(attempt.result);
      return;
    }
    this.error.set(this.i18nService.t(ERROR_KEYS[attempt.error] ?? "l2ErrorGeneric"));
  }
}
