const assert = require("assert");
const snarkjs = require("snarkjs");
const { poseidon3 } = require("poseidon-lite");
const { derivePublicKey } = require("@zk-kit/eddsa-poseidon");
const { Identity } = require("@semaphore-protocol/identity");
const { Group } = require("@semaphore-protocol/group");
const buildBabyjub = require("circomlibjs").buildBabyjub;

const {
    genMasterPk,
    deriveWebKey,
    deriveChildSecretKey,
    deriveChildPublicKey,
    ReplaceCPK,
    VerifyReplacedCPK,
    ProveMPKMemb,
    VerifyMPKMemb,
    createID,
    createSPK,
    authProof,
    authVerify,
    proveMem,
    verifyMem,
    getNullifier,
} = require("../src");
const { channel } = require("diagnostics_channel");
const {stringify} = require("mocha/lib/utils");

describe("Boquila", function () {
    this.timeout(200000);

    describe("Verifying auth proofs", function () {
        it("should generate valid signatures", async function () {
            const msk = "123";
            const id = await createID(msk);
            const message = "Hello World"
            const signature = id.signMessage(message)
            assert.equal(true, Identity.verifySignature(message, signature, id.publicKey));
        });
    });

    describe("Verifying auth proofs for service keys", function () {
        it("should generate valid signatures", async function () {
            const msk = "123";
            const id = await createID(msk);
            const challenge = "Hello World";
            const serviceName = "abc_service";
            const spk = await createSPK(msk, serviceName)
            const signature = spk.signMessage(challenge)
            assert.equal(true, Identity.verifySignature(challenge, signature, spk.publicKey));
        });
    });

    describe("Verifying auth proofs for service keys", function () {
        it("should generate valid signatures", async function () {
            const msk = "123";
            const id = await createID(msk);
            const challenge = "Hello World";
            const serviceName = "abc_service";
            const spk = await createSPK(msk, serviceName)
            const signature = await authProof(msk, challenge, serviceName)
            const val = await authVerify(spk, signature, challenge)
            assert.equal(true, val);
        });
    });

    describe("Verifying membership proofs", function () {
        it("should generate valid proofs", async function () {
            const msk1 = "1";
            const id1 = await createID(msk1);
            const msk2 = "2";
            const id2 = await createID(msk2);
            const msk3 = "3";
            const id3 = await createID(msk3);
            const msk4 = "4";
            const id4 = await createID(msk4);
            
            const challenge = "1234";
            const serviceName = "1234";
            
            const group = new Group([
                id1.commitment, 
                id2.commitment,
                id3.commitment,
                id4.commitment,
            ]);

            const proof = await proveMem(msk1, group, serviceName, challenge);
            const val = await verifyMem(proof, group, serviceName, challenge);
            assert.equal(true, val);
        });
    });

    describe("Verifying the consistency of the nullifier", function () {
        it("Should output the same nullifier even with 2 different groups", async function () {
            const msk1 = "1";
            const id1 = await createID(msk1);
            const msk2 = "2";
            const id2 = await createID(msk2);
            const msk3 = "3";
            const id3 = await createID(msk3);
            const msk4 = "4";
            const id4 = await createID(msk4);

            const challenge = "1234";
            const serviceName = "1234";

            const group1 = new Group([
                id1.commitment,
                id2.commitment,
                id3.commitment,
                id4.commitment,
            ]);

            const group2 = new Group([
                id1.commitment,
                id2.commitment,
                id3.commitment,
            ]);

            const proof1 = await proveMem(msk1, group1, serviceName, challenge);
            const proof2 = await proveMem(msk1, group2, serviceName, challenge);
            const val1 = await verifyMem(proof1, group1, serviceName, challenge);
            const val2 = await verifyMem(proof2, group2, serviceName, challenge);
            const nul1 = getNullifier(proof1);
            const nul2 = getNullifier(proof2);
            assert.equal(true, val1);
            assert.equal(true, val2);
            assert.equal(nul1.toString(), nul2.toString());
        });
    });

    describe("#deriveWebKeys", function () {
        it("should derive web key", async function () {
            const msk = "123";
            const name = "web1";
            const wpk = await deriveWebKey(msk, name);
            assert.equal(wpk.length, 2);
        });
    });

    describe("#deriveChildSecretKey", function () {
        it("should derive child secret key", async function () {
            const msk = "123";
            const name = "web1";
            const count = 0;
            const csk = deriveChildSecretKey(msk, name, count);
            assert.notEqual(csk, null);
        });
    });

    describe("#deriveChildPublicKey", function () {
        it("should derive child public key", async function () {
            const msk = "123";
            const name = "web1";
            const count = 0;
            const csk = deriveChildSecretKey(msk, name, count);
            const cpk = await deriveChildPublicKey(csk);
            assert.equal(cpk.length, 2);
        });
    });

    describe("#ProveMPKMemb/VerifyMPKMemb", function () {
        it("should prove and verify MPK Membership", async function () {
            const sk = "user1";
            const sk2 = "user2";
            const identity = new Identity(sk); // user
            const identity1 = new Identity(sk2);
            const identity2 = new Identity();
            const identity3 = new Identity();
            const message = "1234";

            const group = new Group([
                identity.commitment, // user
                identity1.commitment,
                identity2.commitment,
                identity3.commitment,
            ]);
            const proof = await ProveMPKMemb(sk, group, message);
            const proof2 = await ProveMPKMemb(sk2, group, message);

            const isValid = await VerifyMPKMemb(proof, group, message);
            const isValid2 = await VerifyMPKMemb(proof2, group, message);
            assert.equal(isValid, true);
            assert.equal(isValid2, true);
        });
    });

    describe("Proving time and verification time for membership proofs", function () {
        it("should generate valid proofs", async function () {
            const testcases = 10;
            let provingTime = 0;
            let verificationTime = 0;
            let proofSize = 0;
            for(let groupSize = 8; groupSize <= 1024; groupSize = groupSize*2) {
                let group = new Group([]);
                let identities = [];
                let msks = [];
                for (let j = 0; j < groupSize; j++) {
                    msks[j] = stringify(j);
                    identities[j] = await createID(msks[j]);
                    group.addMember(identities[j].commitment)
                }

                const challenge = "1234";
                const serviceName = "1234";

                function mean(arr) {
                    return arr.reduce((a, b) => a + b, 0) / arr.length;
                }

                function stddev(arr) {
                    const m = mean(arr);
                    return Math.sqrt(arr.reduce((s, x) => s + (x - m) ** 2, 0) / (arr.length-1)); // szhou: should use length-1 here for sample stddev
                }

                // Source - https://stackoverflow.com/a
                // Posted by thomas-peter, modified by community. See post 'Timeline' for change history
                // Retrieved 2025-12-01, License - CC BY-SA 4.0

                function roughSizeOfObject(object) {
                    const objectList = [];
                    const stack = [object];
                    let bytes = 0;

                    while (stack.length) {
                        const value = stack.pop();

                        switch (typeof value) {
                        case 'boolean':
                            bytes += 4;
                            break;
                        case 'string':
                            bytes += value.length * 2;
                            break;
                        case 'number':
                            bytes += 8;
                            break;
                        case 'object':
                            if (!objectList.includes(value)) {
                            objectList.push(value);
                            for (const prop in value) {
                                if (value.hasOwnProperty(prop)) {
                                stack.push(value[prop]);
                                }
                            }
                            }
                            break;
                        }
                    }

                    return bytes;
                }

                const proveTimes = [];
                const proveSizes = [];
                const verifyTimes = [];

                let proof;

                // --- measure prove times per run ---
                for (let i = 0; i < testcases; i++) {
                    const start = performance.now();
                    proof = await proveMem(msks[0], group, serviceName, challenge);
                    const end = performance.now();
                    proveTimes.push(end - start);
                    proveSizes.push(roughSizeOfObject(proof));
                }

                // --- measure verify times per run ---
                let val;
                for (let i = 0; i < testcases; i++) {
                    const start = performance.now();
                    val = await verifyMem(proof, group, serviceName, challenge);
                    const end = performance.now();
                    verifyTimes.push(end - start);
                }

                assert.equal(true, val);

                // --- compute statistics ---
                const proveMean = mean(proveTimes);
                const proveStd  = stddev(proveTimes);

                const psMean = mean(proveSizes);
                const psStd  = stddev(proveSizes);

                const verifyMean = mean(verifyTimes);
                const verifyStd  = stddev(verifyTimes);

                console.log("group size: %d, %d+%d, %d+%d, %d+%d", 
                    groupSize, proveMean.toFixed(3), proveStd.toFixed(3), 
                    verifyMean.toFixed(3), verifyStd.toFixed(3),
                    psMean.toFixed(3), psStd.toFixed(3)
                );

            }
        });
    });

});
