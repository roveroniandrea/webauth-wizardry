import { IssuerMetadata } from 'openid-client';

export type ProviderData = {
    providerName: string;
    issuerMetadata: IssuerMetadata;
    clientId: string;
    clientSecret: string;
}