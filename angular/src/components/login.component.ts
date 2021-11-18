import {
    Directive,
    Input,
    OnDestroy,
    OnInit,
    forwardRef
} from '@angular/core';

import { ControlValueAccessor, FormControl, NG_VALUE_ACCESSOR } from '@angular/forms';



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

import { CaptchaProtectedComponent } from './captchaProtected.component';

const Keys = {
    rememberedEmail: 'rememberedEmail',
    rememberEmail: 'rememberEmail',
};

@Directive(
    {
        providers: [
            {
                provide: NG_VALUE_ACCESSOR,
                useExisting: forwardRef(() => LoginComponent),
                multi: true
            }
        ]
    }
)
export class LoginComponent extends CaptchaProtectedComponent implements OnInit, OnDestroy, ControlValueAccessor {
    @Input() email: string = '';
    @Input() rememberEmail = true;

    masterPasswordBuffer: ArrayBuffer;
    showPassword: boolean = false;
    formPromise: Promise<AuthResult>;
    onSuccessfulLogin: () => Promise<any>;
    onSuccessfulLoginNavigate: () => Promise<any>;
    onSuccessfulLoginTwoFactorNavigate: () => Promise<any>;
    onSuccessfulLoginForceResetNavigate: () => Promise<any>;

    protected twoFactorRoute = '2fa';
    protected successRoute = 'vault';
    protected forcePasswordResetRoute = 'update-temp-password';

    constructor(protected authService: AuthService, protected router: Router,
        platformUtilsService: PlatformUtilsService, i18nService: I18nService,
        protected stateService: StateService, environmentService: EnvironmentService,
        protected passwordGenerationService: PasswordGenerationService,
        protected cryptoFunctionService: CryptoFunctionService, private storageService: StorageService) {
        super(environmentService, i18nService, platformUtilsService);
    }

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

        console.log(Utils.debugStringWithTimestamp('LoginComponent: OnInit'));
    }

    async ngOnDestroy() {
        console.log(Utils.debugStringWithTimestamp('LoginComponent: OnDestroy'));
    }

    async submit() {
        await this.setupCaptcha();

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

        //Check the arraypass we get from the child instead
        if (this.masterPasswordBuffer == null || this.masterPasswordBuffer.byteLength === 0) {
            this.platformUtilsService.showToast('error', this.i18nService.t('errorOccurred'),
                this.i18nService.t('masterPassRequired'));
            return;
        }


        let masterPasswordBufferView = new Uint8Array(this.masterPasswordBuffer);

        try {
            //this.formPromise = this.authService.logIn(this.email, this.masterPassword);
            //console.log('AuthService: ' + this.authService);
            this.formPromise = this.authService.logInWithArrayBuffer(this.email, this.masterPasswordBuffer);

            const response = await this.formPromise;

            //NOTE: Clearing password buffer here since it's needed anymore. It has to be after we receive the answer from the response
            //since it's an async call.
            this.clearArrayBufferToDEAD(masterPasswordBufferView);

            //console.log('After-clean:' + Utils.fromBufferToUtf8(this.masterPasswordBuffer));

            await this.storageService.save(Keys.rememberEmail, this.rememberEmail);
            if (this.rememberEmail) {
                await this.storageService.save(Keys.rememberedEmail, this.email);
            } else {
                await this.storageService.remove(Keys.rememberedEmail);
            }
            if (this.handleCaptchaRequired(response)) {
                return;
            } else if (response.twoFactor) {
                if (this.onSuccessfulLoginTwoFactorNavigate != null) {
                    this.onSuccessfulLoginTwoFactorNavigate();
                } else {
                    this.router.navigate([this.twoFactorRoute]);
                }
            } else if (response.forcePasswordReset) {
                if (this.onSuccessfulLoginForceResetNavigate != null) {
                    this.onSuccessfulLoginForceResetNavigate();
                } else {
                    this.router.navigate([this.forcePasswordResetRoute]);
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
            console.error('THERE WAS AN EXCEPTION: ' + error);
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
        const webUrl = this.environmentService.getWebVaultUrl();

        // Launch browser
        this.platformUtilsService.launchUri(webUrl + '/#/sso?clientId=' + clientId +
            '&redirectUri=' + encodeURIComponent(ssoRedirectUri) +
            '&state=' + state + '&codeChallenge=' + codeChallenge);
    }

    protected focusInput() {
        document.getElementById(this.email == null || this.email === '' ? 'email' : 'masterPassword').focus();
    }

    clearArrayBufferToDEAD(buffer: Uint8Array) {
        const leftover = buffer.length % 4;

        //This clears the password to DEAD (just easy to look for in memory dumps)
        for (let i = 0; i < buffer.length - leftover; i += 4) {
            buffer[i + 0] = 68;
            buffer[i + 1] = 69;
            buffer[i + 2] = 65;
            buffer[i + 3] = 68;
        }

        switch (leftover) {
            case 3: {
                buffer[buffer.length - 3] = 68;
                buffer[buffer.length - 2] = 69;
                buffer[buffer.length - 1] = 65;
                break;
            }
            case 2: {
                buffer[buffer.length - 2] = 68;
                buffer[buffer.length - 1] = 69;
                break;
            }
            case 1: {
                buffer[buffer.length - 1] = 68;
                break;
            }
        }
    }

    receivePass(masterpass: ArrayBuffer) {
        this.masterPasswordBuffer = masterpass;

        const arrayBufferView = new Uint8Array(this.masterPasswordBuffer);

        //console.log('Received pass from child: ' + arrayBufferView);

        this.submit();
    }

    //#region ControlValueAcessor
    //NOTE:This needs to be here because the NGModel has to bind to something. It's never actually written to
    dummyInput : string;

    // Step 3: Copy paste this stuff here
    onChange: any = () => { }
    onTouch: any = () => { }
    registerOnChange(fn: any): void {
        this.onChange = fn;
    }
    registerOnTouched(fn: any): void {
        this.onTouch = fn;
    }

    // Step 4: Define what should happen in this component, if something changes outside
    writeValue(_input: string) {
        //Empty on purpose
    }

    // Step 5: Handle what should happen on the outside, if something changes on the inside
    // in this simple case, we've handled all of that in the .html
    // a) we've bound to the local variable with ngModel
    // b) we emit to the ouside by calling onChange on ngModelChange

    onInsideChange(receivedString: string) {
        //console.log('ReceivedString: ' + receivedString);

        //Clear previous ArrayBuffer
        let inputArrayView = new Uint8Array(this.masterPasswordBuffer);
        //console.log('inputArrayView: Pre-Clear:' + inputArrayView);

        //Clear the previous ArrayBuffer (that contained the old stored password)
        inputArrayView.fill(0);

        //console.log('inputArrayView: After-Clear:' + inputArrayView);


        //Note: important to assing the underlying buffer instead of the view :)
        //TODO: Inline this function and see if it makes a difference. In theory this creates a new string reference so rip
        this.masterPasswordBuffer = Utils.fromUtf8ToArray(receivedString).buffer;

        inputArrayView = new Uint8Array(this.masterPasswordBuffer);
        //console.log('inputArrayView: After-String:' + inputArrayView);

        this.onChange(this.masterPasswordBuffer);
    }

}