import AppClient, { PartialSignature } from './lib/appClient';
import {
  DefaultDescriptorTemplate,
  DefaultWalletPolicy,
  WalletPolicy
} from './lib/policy';
import { PsbtV2 } from './lib/psbtv2';

export {
  AppClient,
  PsbtV2,
  DefaultDescriptorTemplate,
  DefaultWalletPolicy,
  PartialSignature,
  WalletPolicy
};

export default AppClient;
