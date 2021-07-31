import {
    Directive,
    EventEmitter,
    Input,
    OnInit,
    Output,
} from '@angular/core';

import { I18nService } from '../../abstractions/i18n.service';
import { PasswordGenerationService } from '../../abstractions/passwordGeneration.service';
import { PlatformUtilsService } from '../../abstractions/platformUtils.service';

import { PasswordGeneratorPolicyOptions } from '../../models/domain/passwordGeneratorPolicyOptions';

@Directive()
export class PasswordGeneratorComponent implements OnInit {
    @Input() showSelect: boolean = false;
    @Output() onSelected = new EventEmitter<string>();

    options: any = {};
    password: string = '-';
    showOptions = false;
    avoidAmbiguous = false;
    enforcedPolicyOptions: PasswordGeneratorPolicyOptions;
    websitePasswordOptions: any = {};

    constructor(protected passwordGenerationService: PasswordGenerationService,
        protected platformUtilsService: PlatformUtilsService, protected i18nService: I18nService,
        private win: Window) { }

    async ngOnInit() {
        const optionsResponse = await this.passwordGenerationService.getOptions();
        const websiteOptionsResponse = await this.passwordGenerationService.getWebsiteOptions();
        this.options = optionsResponse[0];
        this.websitePasswordOptions = websiteOptionsResponse[0];
        console.log("@ pw generator component PARENT -> ", this.options);
        console.log("@ pw generator component PARENT website  -> ", websiteOptionsResponse[0]);
        this.enforcedPolicyOptions = optionsResponse[1];
        this.avoidAmbiguous = !this.options.ambiguous;
        this.options.type = this.options.type === 'passphrase' ? 'passphrase' : 'password';
        this.password = await this.passwordGenerationService.generatePassword(this.options);
        console.log("@ngOnInit => password is this => ", this.password);
        await this.passwordGenerationService.addHistory(this.password);
    }

    async sliderChanged() {
        this.saveOptions(false);
        await this.passwordGenerationService.addHistory(this.password);
    }

    async sliderInput() {
        this.normalizeOptions();
        console.log("component-parent: this are the options -> ", this.options);
        console.log("component-parent: this are the WEBSITE options -> ", this.websitePasswordOptions);

        this.password = await this.passwordGenerationService.generatePassword(this.options);

    }

    async saveOptions(regenerate: boolean = true) {
        this.normalizeOptions();
        await this.passwordGenerationService.saveOptions(this.options);

        if (regenerate) {
            await this.regenerate();
        }
    }

    async regenerate() {
        console.log("component-parent: regenerate(): options -> ", this.options);
        this.password = await this.passwordGenerationService.generatePassword(this.options);
        await this.passwordGenerationService.addHistory(this.password);
    }

    copy() {
        const copyOptions = this.win != null ? { window: this.win } : null;
        this.platformUtilsService.copyToClipboard(this.password, copyOptions);
        this.platformUtilsService.showToast('info', null,
            this.i18nService.t('valueCopied', this.i18nService.t('password')));
    }

    select() {
        this.onSelected.emit(this.password);
    }

    toggleOptions() {
        this.showOptions = !this.showOptions;
    }

    private normalizeOptions() {
        // Application level normalize options depedent on class variables
        this.options.ambiguous = !this.avoidAmbiguous;

        if (!this.options.uppercase && !this.options.lowercase && !this.options.number && !this.options.special) {
            this.options.lowercase = true;
            if (this.win != null) {
                const lowercase = this.win.document.querySelector('#lowercase') as HTMLInputElement;
                if (lowercase) {
                    lowercase.checked = true;
                }
            }
        }

        this.passwordGenerationService.normalizeOptions(this.options, this.enforcedPolicyOptions);
    }
}
