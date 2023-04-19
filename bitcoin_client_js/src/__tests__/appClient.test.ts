
import fs from 'fs';
import path from 'path';
import process from 'process';

import { ChildProcessWithoutNullStreams, spawn } from "child_process";

import SpeculosTransport from "@ledgerhq/hw-transport-node-speculos-http";

import type { SpeculosHttpTransportOpts } from "@ledgerhq/hw-transport-node-speculos-http";

import { listen } from "@ledgerhq/logs";
import type { Log } from "@ledgerhq/logs";


import { AppClient, DefaultWalletPolicy, PsbtV2, WalletPolicy } from ".."

jest.setTimeout(10000);


/*
This currently does not work if the app is compiled with DEBUG=1; this seems to be inherited from the fact that
@ledgerhq/hw-transport-node-speculos-http seems to be malfunctioning in that case.

The LOG_SPECULOS and LOG_APDUS environment variables can be used to log, respectively, the output of the speculos
process and all the APDUs exchanged during the tests.
*/


const repoRootPath = path.resolve(process.cwd(), '..')

const speculos_path = process.env.SPECULOS || "speculos.py";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function openSpeculosAndWait(opts: SpeculosHttpTransportOpts = {}): Promise<SpeculosTransport> {
  for (let i = 0; ; i++) {
    try {
      return await SpeculosTransport.open(opts);
    } catch (e) {
      if (i > 50) {
        throw e;
      }
    }
    await sleep(100);
  }
}

// Convenience method to send the kill signal and wait for the process to completely terminate
async function killProcess(proc: ChildProcessWithoutNullStreams, signal: NodeJS.Signals = 'SIGTERM', timeout = 10000) {
  return new Promise<void>((resolve, reject) => {
    const pid = proc.pid;
    process.kill(pid, signal);
    let count = 0;
    const intervalHandler = setInterval(() => {
      try {
        process.kill(pid, signal);
      } catch (e) {
        clearInterval(intervalHandler);
        resolve();
      }
      if ((count += 100) > timeout) {
        clearInterval(intervalHandler);
        reject(new Error("Timeout process kill"))
      }
    }, 100)
  });
}

// Sets the speculos automation file using the REST api.
// TODO: It would be better to add this in SpeculosTransport, or create a new custom class.
async function setSpeculosAutomation(transport: SpeculosTransport, automationObj: any): Promise<void> {
  return new Promise((resolve, reject) => {
      transport.instance
        .post(`/automation`, automationObj)
        .then((response) => {
          resolve(response.data);
        }, reject);
    });
}


describe("test AppClient", () => {
  let sp: ChildProcessWithoutNullStreams;
  let transport: SpeculosTransport;
  let app: AppClient;

  beforeAll(async () => {
    if (process.env.LOG_APDUS) {
      listen((arg: Log) => {
        if (arg.type == 'apdu') {
          console.log("apdu:", arg.message);
        }
      });
    }
  });

  beforeEach(async () => {
    sp = spawn(speculos_path, [
      repoRootPath + "/bin/app.elf",
      '-k', '2.1',
      '--model', 'nanos',
      '--display', 'headless'
    ]);
    
    sp.stdout.on('data', function(data) {
      if (process.env.LOG_SPECULOS) {
        console.log('stdout: ' + data);
      }
    });

    sp.stderr.on('data', function(data) {
      if (process.env.LOG_SPECULOS) {
        console.log('stderr: ' + data);
      }
    });

    transport = await openSpeculosAndWait();
    app = new AppClient(transport);
  });

  afterEach(async () => {
    await transport.close();
    await killProcess(sp);
  });

  it("can retrieve the app's version", async () => {
    const result = await app.getAppAndVersion();
    expect(result.name).toEqual("Bitcoin Test");
    expect(result.version.split(".")[0]).toEqual("2")
  });

  it("can retrieve the master fingerprint", async () => {
    const result = await app.getMasterFingerprint();
    expect(result).toEqual("f5acc2fd");
  });

  it("can get an extended pubkey", async () => {
    const result = await app.getExtendedPubkey("m/49'/1'/1'/1/3", false);

    expect(result).toEqual("tpubDGnetmJDCL18TyaaoyRAYbkSE9wbHktSdTS4mfsR6inC8c2r6TjdBt3wkqEQhHYPtXpa46xpxDaCXU2PRNUGVvDzAHPG6hHRavYbwAGfnFr")
  });

  it("can get wallet addresses", async () => {
    const testcases: {
      policy: WalletPolicy,
      change: 0 | 1,
      addrIndex: number,
      expResult: string,
      walletHmac?: Buffer
    }[] = [
      // legacy
      {
        policy: new DefaultWalletPolicy("pkh(@0/**)", "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"),
        change: 0,
        addrIndex: 0,
        expResult: "mz5vLWdM1wHVGSmXUkhKVvZbJ2g4epMXSm",
      },
      {
        policy: new DefaultWalletPolicy("pkh(@0/**)", "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"),
        change: 1,
        addrIndex: 15,
        expResult: "myFCUBRCKFjV7292HnZtiHqMzzHrApobpT",
      },
      // native segwit
      {
        policy: new DefaultWalletPolicy("wpkh(@0/**)", "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"),
        change: 0,
        addrIndex: 0,
        expResult: "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk",
      },
      {
        policy: new DefaultWalletPolicy("wpkh(@0/**)", "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"),
        change: 1,
        addrIndex: 15,
        expResult: "tb1qlrvzyx8jcjfj2xuy69du9trtxnsvjuped7e289",
      },
      // wrapped segwit
      {
        policy: new DefaultWalletPolicy("sh(wpkh(@0/**))", "[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3"),
        change: 0,
        addrIndex: 0,
        expResult: "2MyHkbusvLomaarGYMqyq7q9pSBYJRwWcsw",
      },
      {
        policy: new DefaultWalletPolicy("sh(wpkh(@0/**))", "[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3"),
        change: 1,
        addrIndex: 15,
        expResult: "2NAbM4FSeBQG4o85kbXw2YNfKypcnEZS9MR",
      },
      // taproot
      {
        policy: new DefaultWalletPolicy("tr(@0/**)", "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"),
        change: 0,
        addrIndex: 0,
        expResult: "tb1pws8wvnj99ca6acf8kq7pjk7vyxknah0d9mexckh5s0vu2ccy68js9am6u7",
      },
      {
        policy: new DefaultWalletPolicy("tr(@0/**)", "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"),
        change: 0,
        addrIndex: 9,
        expResult: "tb1psl7eyk2jyjzq6evqvan854fts7a5j65rth25yqahkd2a765yvj0qggs5ne",
      },
      {
        policy: new DefaultWalletPolicy("tr(@0/**)", "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"),
        change: 1,
        addrIndex: 0,
        expResult: "tb1pmr60r5vfjmdkrwcu4a2z8h39mzs7a6wf2rfhuml6qgcp940x9cxs7t9pdy",
      },
      {
        policy: new DefaultWalletPolicy("tr(@0/**)", "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"),
        change: 1,
        addrIndex: 9,
        expResult: "tb1p98d6s9jkf0la8ras4nnm72zme5r03fexn29e3pgz4qksdy84ndpqgjak72",
      },
      // multisig
      {
        policy: new WalletPolicy(
          "Cold storage",
          "wsh(sortedmulti(2,@0/**,@1/**))",
          [
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
          ]
        ),
        change: 0,
        addrIndex: 0,
        expResult: "tb1qmyauyzn08cduzdqweexgna2spwd0rndj55fsrkefry2cpuyt4cpsn2pg28",
        walletHmac: Buffer.from("d7c7a60b4ab4a14c1bf8901ba627d72140b2fb907f2b4e35d2e693bce9fbb371", "hex")
      },
    ];

    for (const { policy, change, addrIndex, expResult, walletHmac } of testcases) {
      const result = await app.getWalletAddress(policy, walletHmac || null, change, addrIndex, false);
      expect(result).toEqual(expResult);  
    }
  });


  it("can register a multisig wallet", async () => {
    const walletPolicy = new WalletPolicy(
      "Cold storage",
      "wsh(sortedmulti(2,@0/**,@1/**))",
      [
        "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
        "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
      ]
    );

    const automation = JSON.parse(fs.readFileSync('src/__tests__/automations/register_wallet_accept.json').toString());
    await setSpeculosAutomation(transport, automation);

    const [walletId, walletHmac] = await app.registerWallet(walletPolicy);

    expect(walletId).toEqual(walletPolicy.getId());
    expect(walletHmac.length).toEqual(32);
  });

  it("can register a miniscript wallet", async () => {
    const walletPolicy = new WalletPolicy(
      "Decaying 3-of-3",
      "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
      [
        "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
        "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
      ]
    );

    const automation = JSON.parse(fs.readFileSync('src/__tests__/automations/register_wallet_accept.json').toString());
    await setSpeculosAutomation(transport, automation);

    const [walletId, walletHmac] = await app.registerWallet(walletPolicy);

    expect(walletId).toEqual(walletPolicy.getId());
    expect(walletHmac.length).toEqual(32);
  });

  it("can sign a psbt", async () => {
    // psbt from test_sign_psbt_singlesig_wpkh_2to2 in the main test suite, converted to PSBTv2
    const psbtBuf = Buffer.from(
      "cHNidP8BAAoBAAAAAAAAAAAAAQIEAgAAAAEDBAAAAAABBAECAQUBAgH7BAIAAAAAAQBxAgAAAAGTarLgEHL3k8/kyXdU3hth/gPn22U2yLLyHdC1dCxIRQEAAAAA/v///wLe4ccAAAAAABYAFOt418QL8QY7Dj/OKcNWW2ichVmrECcAAAAAAAAWABQjGNZvhP71xIdfkzsDjcY4MfjaE/mXHgABAR8QJwAAAAAAABYAFCMY1m+E/vXEh1+TOwONxjgx+NoTIgYDRV7nztyXsLpDW4AGb8ksljo0xgAxeYHRNTMMTuQ6x6MY9azC/VQAAIABAACAAAAAgAAAAAABAAAAAQ4gniz+J/Cth7eKI31ddAXUowZmyjYdWFpGew3+QiYrTbQBDwQBAAAAARAE/f///wESBAAAAAAAAQBxAQAAAAEORx706Sway1HvyGYPjT9pk26pybK/9y/5vIHFHvz0ZAEAAAAAAAAAAAJgrgoAAAAAABYAFDXG4N1tPISxa6iF3Kc6yGPQtZPsrwYyAAAAAAAWABTcKG4M0ua9N86+nsNJ+18IkFZy/AAAAAABAR9grgoAAAAAABYAFDXG4N1tPISxa6iF3Kc6yGPQtZPsIgYCcbW3ea2HCDhYd5e89vDHrsWr52pwnXJPSNLibPh08KAY9azC/VQAAIABAACAAAAAgAEAAAAAAAAAAQ4gr7+uBlkPdB/xr1m2rEYRJjNqTEqC21U99v76tzesM/MBDwQAAAAAARAE/f///wESBAAAAAAAIgICKexHcnEx7SWIogxG7amrt9qm9J/VC6/nC5xappYcTswY9azC/VQAAIABAACAAAAAgAEAAAAKAAAAAQMIqDoGAAAAAAABBBYAFOs4+puBKPgfJule2wxf+uqDaQ/kAAEDCOCTBAAAAAAAAQQiACA/qWbJ3c3C/ZbkpeG8dlufr2zos+tPEQSq1r33cyTlvgA=",
      "base64"
    );

    const automation = JSON.parse(fs.readFileSync('src/__tests__/automations/sign_with_wallet_accept.json').toString());
    await setSpeculosAutomation(transport, automation);

    const walletPolicy = new DefaultWalletPolicy(
      "wpkh(@0/**)",
      "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
    );

    const psbt = new PsbtV2();
    psbt.deserialize(psbtBuf);
    const result = await app.signPsbt(psbt, walletPolicy, null, () => {});

    expect(result.length).toEqual(2);

    expect(result[0][0]).toEqual(0);
    expect(result[0][1].pubkey).toEqual(Buffer.from(
      "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3",
      "hex"
    ));
    expect(result[0][1].signature).toEqual(Buffer.from(
      "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01",
      "hex"
    ));


    expect(result[1][0]).toEqual(1);
    expect(result[1][1].pubkey).toEqual(Buffer.from(
      "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0",
      "hex"
    ));
    expect(result[1][1].signature).toEqual(Buffer.from(
      "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001",
      "hex"
    ));
    expect(result[1][1].tapleafHash).toBeUndefined();
  });

  it("can sign a psbt for a taproot script path", async () => {
    // psbt from test_sign_psbt_tr_script_pk_sighash_all in the main test suite, converted to PSBTv2
    const psbtBuf = Buffer.from(
      "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAfsEAgAAAAABAStMBgAAAAAAACJRIPwKENMIx+QbS7w2Qvj9isKJhTsc51WgxtDUlfA9ny2kAQMEAQAAACIVwVAXEIvs6o3txTALsiOGs6swNnrCYvnOXlgybrg+OiL1IyBrFujB+Xn6TMDwW2owCv//lBRZtvIN533lWwFg745MrKzAIRZQFxCL7OqN7cUwC7IjhrOrMDZ6wmL5zl5YMm64Pjoi9R0AdiI6bjAAAIABAACAAAAAgAIAAIAAAAAAAAAAACEWaxbowfl5+kzA8FtqMAr//5QUWbbyDed95VsBYO+OTKw9AQku2gM2F+IQ7n99DjeKQErqHEi1aqEDAivs93RuRwCk9azC/TAAAIABAACAAAAAgAIAAIAAAAAAAAAAAAEXIFAXEIvs6o3txTALsiOGs6swNnrCYvnOXlgybrg+OiL1ARggCS7aAzYX4hDuf30ON4pASuocSLVqoQMCK+z3dG5HAKQBDiAfwcxXccuDhgzFbZS8/tk4YIwX9jZiQ1tB6cRP/P0xQgEPBAEAAAABEAT9////AAEDCDkFAAAAAAAAAQQWABSqjvN0yvrfynaQLdtc9hxgu/2dhQA=",
      "base64"
    );

    const automation = JSON.parse(fs.readFileSync('src/__tests__/automations/sign_with_wallet_accept.json').toString());
    await setSpeculosAutomation(transport, automation);

    const walletPolicy = new WalletPolicy(
      "Taproot foreign internal key, and our script key",
      "tr(@0/**,pk(@1/**))",
      [
        "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
        "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
      ]
    );

    const psbt = new PsbtV2();
    psbt.deserialize(psbtBuf);
    const hmac = Buffer.from("dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7", "hex");
    const result = await app.signPsbt(psbt, walletPolicy, hmac);

    expect(result.length).toEqual(1);

    expect(result[0][0]).toEqual(0);
    expect(result[0][1].pubkey).toEqual(Buffer.from(
      "6b16e8c1f979fa4cc0f05b6a300affff941459b6f20de77de55b0160ef8e4cac",
      "hex"
    ));
    expect(result[0][1].tapleafHash).toEqual(Buffer.from(
      "092eda033617e210ee7f7d0e378a404aea1c48b56aa103022becf7746e4700a4",
      "hex"
    ));

    // We could test the validity of the signature, but this is already done in the corresponding python test.
    // Here we're only interested in testing that the JS library returns the correct values.
    expect(result[0][1].signature.length).toEqual(65); // 65 because it's SIGHASH_ALL and not SIGHASH_DEFAULT
  });

  it("can sign a psbt passed as a base64 string", async () => {
    const automation = JSON.parse(fs.readFileSync('src/__tests__/automations/sign_with_wallet_accept.json').toString());
    await setSpeculosAutomation(transport, automation);

    const walletPolicy = new WalletPolicy(
      "Taproot foreign internal key, and our script key",
      "tr(@0/**,pk(@1/**))",
      [
        "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
        "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
      ]
    );

    const hmac = Buffer.from("dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7", "hex");
    const psbtBase64 = "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAfsEAgAAAAABAStMBgAAAAAAACJRIPwKENMIx+QbS7w2Qvj9isKJhTsc51WgxtDUlfA9ny2kAQMEAQAAACIVwVAXEIvs6o3txTALsiOGs6swNnrCYvnOXlgybrg+OiL1IyBrFujB+Xn6TMDwW2owCv//lBRZtvIN533lWwFg745MrKzAIRZQFxCL7OqN7cUwC7IjhrOrMDZ6wmL5zl5YMm64Pjoi9R0AdiI6bjAAAIABAACAAAAAgAIAAIAAAAAAAAAAACEWaxbowfl5+kzA8FtqMAr//5QUWbbyDed95VsBYO+OTKw9AQku2gM2F+IQ7n99DjeKQErqHEi1aqEDAivs93RuRwCk9azC/TAAAIABAACAAAAAgAIAAIAAAAAAAAAAAAEXIFAXEIvs6o3txTALsiOGs6swNnrCYvnOXlgybrg+OiL1ARggCS7aAzYX4hDuf30ON4pASuocSLVqoQMCK+z3dG5HAKQBDiAfwcxXccuDhgzFbZS8/tk4YIwX9jZiQ1tB6cRP/P0xQgEPBAEAAAABEAT9////AAEDCDkFAAAAAAAAAQQWABSqjvN0yvrfynaQLdtc9hxgu/2dhQA="
    const result = await app.signPsbt(psbtBase64, walletPolicy, hmac);

    expect(result.length).toEqual(1);
  });

  it("can sign a psbt passed as binary buffer string", async () => {
    const automation = JSON.parse(fs.readFileSync('src/__tests__/automations/sign_with_wallet_accept.json').toString());
    await setSpeculosAutomation(transport, automation);

    const walletPolicy = new WalletPolicy(
      "Taproot foreign internal key, and our script key",
      "tr(@0/**,pk(@1/**))",
      [
        "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
        "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
      ]
    );

    const hmac = Buffer.from("dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7", "hex");
    const psbtBuf = Buffer.from(
      "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAfsEAgAAAAABAStMBgAAAAAAACJRIPwKENMIx+QbS7w2Qvj9isKJhTsc51WgxtDUlfA9ny2kAQMEAQAAACIVwVAXEIvs6o3txTALsiOGs6swNnrCYvnOXlgybrg+OiL1IyBrFujB+Xn6TMDwW2owCv//lBRZtvIN533lWwFg745MrKzAIRZQFxCL7OqN7cUwC7IjhrOrMDZ6wmL5zl5YMm64Pjoi9R0AdiI6bjAAAIABAACAAAAAgAIAAIAAAAAAAAAAACEWaxbowfl5+kzA8FtqMAr//5QUWbbyDed95VsBYO+OTKw9AQku2gM2F+IQ7n99DjeKQErqHEi1aqEDAivs93RuRwCk9azC/TAAAIABAACAAAAAgAIAAIAAAAAAAAAAAAEXIFAXEIvs6o3txTALsiOGs6swNnrCYvnOXlgybrg+OiL1ARggCS7aAzYX4hDuf30ON4pASuocSLVqoQMCK+z3dG5HAKQBDiAfwcxXccuDhgzFbZS8/tk4YIwX9jZiQ1tB6cRP/P0xQgEPBAEAAAABEAT9////AAEDCDkFAAAAAAAAAQQWABSqjvN0yvrfynaQLdtc9hxgu/2dhQA=",
      "base64"
    );
    const result = await app.signPsbt(psbtBuf, walletPolicy, hmac);

    expect(result.length).toEqual(1);
  });

  it("can sign a message", async () => {
    const msg = "The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible.";
    const path = "m/84'/1'/0'/0/8";

    const automation = JSON.parse(fs.readFileSync('src/__tests__/automations/sign_message_accept.json').toString());
    await setSpeculosAutomation(transport, automation);

    const result = await app.signMessage(Buffer.from(msg, "ascii"), path)
    expect(result).toEqual("H4frM6TYm5ty1MAf9o/Zz9Qiy3VEldAYFY91SJ/5nYMAZY1UUB97fiRjKW8mJit2+V4OCa1YCqjDqyFnD9Fw75k=");
  });
});