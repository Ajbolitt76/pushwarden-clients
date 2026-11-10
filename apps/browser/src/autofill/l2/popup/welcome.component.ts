import { ChangeDetectionStrategy, Component, inject } from "@angular/core";
import { Router } from "@angular/router";

import { JslibModule } from "@bitwarden/angular/jslib.module";
import { PushWardenShield } from "@bitwarden/assets/svg";
import {
  ButtonModule,
  CardComponent,
  SectionComponent,
  SectionHeaderComponent,
  SvgModule,
  TypographyModule,
} from "@bitwarden/components";

import { PopupFooterComponent } from "../../../platform/popup/layout/popup-footer.component";
import { PopupPageComponent } from "../../../platform/popup/layout/popup-page.component";
import { IntroCarouselService } from "../../../vault/popup/services/intro-carousel.service";

/** First-launch PushWarden welcome; replaces Bitwarden's intro carousel and is reachable from About. */
@Component({
  selector: "app-pushwarden-welcome",
  templateUrl: "welcome.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    JslibModule,
    ButtonModule,
    CardComponent,
    PopupFooterComponent,
    PopupPageComponent,
    SectionComponent,
    SectionHeaderComponent,
    SvgModule,
    TypographyModule,
  ],
})
export class WelcomeComponent {
  private readonly router = inject(Router);
  private readonly introCarouselService = inject(IntroCarouselService);

  protected readonly shield = PushWardenShield;

  protected async getStarted() {
    await this.introCarouselService.setIntroCarouselDismissed();
    // Logged-in users opening this from About are sent on to their vault by the login guard.
    await this.router.navigate(["/login"]);
  }
}
