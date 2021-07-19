import {
    Directive,
    Input,
    OnInit,
} from '@angular/core';

import { Router } from '@angular/router';

import { AuthResult } from 'jslib-common/models/domain/authResult';

import { AuthService } from 'jslib-common/abstractions/auth.service';
import { CryptoFunctionService } from 'jslib-common/abstractions/cryptoFunction.service';
import { EnvironmentService } from 'jslib-common/abstractions/environment.service';
import { I18nService } from 'jslib-common/abstractions/i18n.service';
import { PasswordGenerationService } from 'jslib-common/abstractions/passwordGeneration.service';
import { PlatformUtilsService } from 'jslib-common/abstractions/platformUtils.service';
import { StateService } from 'jslib-common/abstractions/state.service';
import { StorageService } from 'jslib-common/abstractions/storage.service';

import { ConstantsService } from 'jslib-common/services/constants.service';

import { Utils } from 'jslib-common/misc/utils';

const Keys = {
    rememberedEmail: 'rememberedEmail',
    rememberEmail: 'rememberEmail',
};

@Directive()
export class LoginComponent implements OnInit {
    @Input() email: string = '';
    @Input() rememberEmail = true;

    masterPassword: string = '';
    showPassword: boolean = false;
    formPromise: Promise<AuthResult>;
    onSuccessfulLogin: () => Promise<any>;
    onSuccessfulLoginNavigate: () => Promise<any>;
    onSuccessfulLoginTwoFactorNavigate: () => Promise<any>;

    protected twoFactorRoute = '2fa';
    protected successRoute = 'vault';

    constructor(protected authService: AuthService, protected router: Router,
        protected platformUtilsService: PlatformUtilsService, protected i18nService: I18nService,
        protected stateService: StateService, protected environmentService: EnvironmentService,
        protected passwordGenerationService: PasswordGenerationService,
        protected cryptoFunctionService: CryptoFunctionService, private storageService: StorageService) { }

    async ngOnInit() {
        if (this.email == null || this.email === '') {
            this.email = await this.storageService.get<string>(Keys.rememberedEmail);
            if (this.email == null) {
                this.email = '';
            }
        }
        this.rememberEmail = await this.storageService.get<boolean>(Keys.rememberEmail);
        if (this.rememberEmail == null) {
            this.rememberEmail = true;
        }
        if (Utils.isBrowser && !Utils.isNode) {
            this.focusInput();
        }
    }

    async submit() {
        if (this.email == null || this.email === '') {
            this.platformUtilsService.showToast('error', this.i18nService.t('errorOccurred'),
                this.i18nService.t('emailRequired'));
            return;
        }
        if (this.email.indexOf('@') === -1) {
            this.platformUtilsService.showToast('error', this.i18nService.t('errorOccurred'),
                this.i18nService.t('invalidEmail'));
            return;
        }
        if (this.masterPassword == null || this.masterPassword === '') {
            this.platformUtilsService.showToast('error', this.i18nService.t('errorOccurred'),
                this.i18nService.t('masterPassRequired'));
            return;
        }

        //TEST: Testing stuff
        let masterPasswordBuffer : ArrayBuffer;
        masterPasswordBuffer = Utils.fromUtf8ToArray(this.masterPassword).buffer;
        
        let test2 : ArrayBuffer;
        test2 = Utils.fromUtf8ToArray('lole');
        
        //console.log('Are test and test2 the same? Should be false: ' + (test === test2));
        //console.log('Pre-clean:' + test + '. Data: ' + Utils.fromBufferToUtf8(test));
        
        let testArrayView = new Int8Array(masterPasswordBuffer);
        //testArrayView.fill(123);

        //console.log('Are these two the same memory address? ' + (testArrayView.buffer === test));
        console.log('After-clean:' + masterPasswordBuffer + '. Data: ' + Utils.fromBufferToUtf8(masterPasswordBuffer));

        try {
            //this.formPromise = this.authService.logIn(this.email, this.masterPassword);
            //console.log('AuthService: ' + this.authService);
            this.formPromise = this.authService.logInWithArrayBuffer(this.email, masterPasswordBuffer);
            
            

            const response = await this.formPromise;
            
            console.log(this.formPromise);

            await this.storageService.save(Keys.rememberEmail, this.rememberEmail);
            if (this.rememberEmail) {
                await this.storageService.save(Keys.rememberedEmail, this.email);
            } else {
                await this.storageService.remove(Keys.rememberedEmail);
            }
            if (response.twoFactor) {
                if (this.onSuccessfulLoginTwoFactorNavigate != null) {
                    this.onSuccessfulLoginTwoFactorNavigate();
                } else {
                    this.router.navigate([this.twoFactorRoute]);
                }
            } else {
                const disableFavicon = await this.storageService.get<boolean>(ConstantsService.disableFaviconKey);
                await this.stateService.save(ConstantsService.disableFaviconKey, !!disableFavicon);
                if (this.onSuccessfulLogin != null) {
                    this.onSuccessfulLogin();
                }
                if (this.onSuccessfulLoginNavigate != null) {
                    this.onSuccessfulLoginNavigate();
                } else {
                    this.router.navigate([this.successRoute]);
                }
            }
        } catch (error) {
            console.error('THERE WAS AN EXCEPTION RETARD ' + error);
         }
    }

    togglePassword() {
        this.showPassword = !this.showPassword;
        document.getElementById('masterPassword').focus();
    }

    async launchSsoBrowser(clientId: string, ssoRedirectUri: string) {
        // Generate necessary sso params
        const passwordOptions: any = {
            type: 'password',
            length: 64,
            uppercase: true,
            lowercase: true,
            numbers: true,
            special: false,
        };
        const state = await this.passwordGenerationService.generatePassword(passwordOptions);
        const ssoCodeVerifier = await this.passwordGenerationService.generatePassword(passwordOptions);
        const codeVerifierHash = await this.cryptoFunctionService.hash(ssoCodeVerifier, 'sha256');
        const codeChallenge = Utils.fromBufferToUrlB64(codeVerifierHash);

        // Save sso params
        await this.storageService.save(ConstantsService.ssoStateKey, state);
        await this.storageService.save(ConstantsService.ssoCodeVerifierKey, ssoCodeVerifier);

        // Build URI
        const webUrl = this.environmentService.getWebVaultUrl() == null ? 'https://vault.bitwarden.com' :
            this.environmentService.getWebVaultUrl();

        // Launch browser
        this.platformUtilsService.launchUri(webUrl + '/#/sso?clientId=' + clientId +
            '&redirectUri=' + encodeURIComponent(ssoRedirectUri) +
            '&state=' + state + '&codeChallenge=' + codeChallenge);
    }

    protected focusInput() {
        document.getElementById(this.email == null || this.email === '' ? 'email' : 'masterPassword').focus();
    }
}
