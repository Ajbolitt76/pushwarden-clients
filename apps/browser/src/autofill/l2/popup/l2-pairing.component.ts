import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  OnDestroy,
  OnInit,
  effect,
  inject,
  signal,
  viewChild,
} from "@angular/core";
import { FormBuilder, ReactiveFormsModule, Validators } from "@angular/forms";
import QRious from "qrious";

import "./qrious.types";

import { JslibModule } from "@bitwarden/angular/jslib.module";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import {
  AsyncActionsModule,
  ButtonModule,
  CardComponent,
  FormFieldModule,
  LinkModule,
  SectionComponent,
  TypographyModule,
} from "@bitwarden/components";

import { BrowserApi } from "../../../platform/browser/browser-api";
import { PopOutComponent } from "../../../platform/popup/components/pop-out.component";
import { PopupHeaderComponent } from "../../../platform/popup/layout/popup-header.component";
import { PopupPageComponent } from "../../../platform/popup/layout/popup-page.component";

interface L2Status {
  paired: boolean;
  phoneId?: string;
  relayUrl?: string;
}

type Response<T> = { result?: T; error?: { code?: string; message?: string } };

/** Settings page: pair this extension with a phone for L2 fill approvals (PROTOCOL.md §5). */
@Component({
  templateUrl: "l2-pairing.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    JslibModule,
    AsyncActionsModule,
    ButtonModule,
    CardComponent,
    FormFieldModule,
    LinkModule,
    PopOutComponent,
    PopupHeaderComponent,
    PopupPageComponent,
    ReactiveFormsModule,
    SectionComponent,
    TypographyModule,
  ],
})
export class L2PairingComponent implements OnInit, OnDestroy {
  private readonly i18nService = inject(I18nService);

  protected readonly status = signal<L2Status | null>(null);
  /** Set while a pairing waits for the user to compare phrases. */
  protected readonly phrase = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  /** The `pushwarden://pair` URI while the QR code is shown (PROTOCOL.md §5b). */
  protected readonly qrUri = signal<string | null>(null);
  /** Show the manual (phone ID + words) form instead of the QR code. */
  protected readonly manual = signal(false);
  private readonly qrCanvas = viewChild<ElementRef<HTMLCanvasElement>>("qrCanvas");

  protected readonly form = inject(FormBuilder).group({
    relayUrl: ["", Validators.required],
    phoneId: ["", Validators.pattern(/^[0-9a-z]{4}-[0-9a-z]{4}$/)],
    pcName: ["", Validators.maxLength(64)],
  });

  constructor() {
    effect(() => {
      const uri = this.qrUri();
      const canvas = this.qrCanvas()?.nativeElement;
      if (uri && canvas) {
        new QRious({ element: canvas, value: uri, size: 240, level: "M" });
      }
    });
  }

  /** Shows the QR code, then waits until the phone scanned it and proved it. */
  protected readonly showQr = async () => {
    this.error.set(null);
    const v = this.form.value;
    const r = await BrowserApi.sendMessageWithResponse<Response<{ uri: string }>>("l2QrStart", {
      relayUrl: v.relayUrl?.trim(),
      pcName: v.pcName || navigatorPcName(),
    });
    if (!r?.result) {
      this.showError(r);
      return;
    }
    this.qrUri.set(r.result.uri);
    const done =
      await BrowserApi.sendMessageWithResponse<Response<{ phoneId: string }>>("l2QrWait");
    this.qrUri.set(null);
    if (done?.error) {
      this.showError(done);
    }
    await this.refresh();
  };

  async ngOnInit() {
    await this.refresh();
  }

  ngOnDestroy() {
    if (this.phrase() || this.qrUri()) {
      void BrowserApi.sendMessageWithResponse("l2PairCancel");
    }
  }

  protected readonly start = async () => {
    this.error.set(null);
    const v = this.form.value;
    if (!v.phoneId) {
      this.error.set(this.i18nService.t("l2PhoneIdRequired"));
      return;
    }
    const r = await BrowserApi.sendMessageWithResponse<Response<{ phrase: string }>>(
      "l2PairStart",
      {
        relayUrl: v.relayUrl?.trim(),
        phoneId: v.phoneId?.trim().toLowerCase(),
        pcName: v.pcName ?? "",
      },
    );
    if (r?.result) {
      this.phrase.set(r.result.phrase);
    } else {
      this.showError(r);
    }
  };

  /** The user saw the same words on both screens; waits for the phone's approval. */
  protected readonly confirm = async () => {
    const r = await BrowserApi.sendMessageWithResponse<Response<void>>("l2PairConfirm");
    this.phrase.set(null);
    if (r?.error) {
      this.showError(r);
    }
    await this.refresh();
  };

  protected readonly cancel = async () => {
    await BrowserApi.sendMessageWithResponse("l2PairCancel");
    this.phrase.set(null);
    this.qrUri.set(null);
  };

  protected readonly unpair = async () => {
    await BrowserApi.sendMessageWithResponse("l2Unpair");
    await this.refresh();
  };

  private async refresh() {
    const r = await BrowserApi.sendMessageWithResponse<Response<L2Status>>("l2Status");
    this.status.set(r?.result ?? null);
    if (r?.result?.relayUrl) {
      this.form.patchValue({ relayUrl: r.result.relayUrl });
    }
  }

  private showError(r: Response<unknown> | undefined) {
    const code = r?.error?.code;
    this.error.set(
      this.i18nService.t(
        code === "timeout"
          ? "l2ErrorTimeout"
          : code === "relayError"
            ? "l2ErrorRelay"
            : "l2ErrorPairing",
      ),
    );
  }
}

/** A default computer name, e.g. "Chrome on Windows". */
function navigatorPcName(): string {
  const ua = navigator.userAgent;
  const browser = ua.includes("Firefox/") ? "Firefox" : ua.includes("Edg/") ? "Edge" : "Chrome";
  const os = ua.includes("Windows") ? "Windows" : ua.includes("Mac OS") ? "macOS" : "Linux";
  return `${browser} on ${os}`;
}
