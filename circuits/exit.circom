pragma circom 2.2.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// Terminal spend: consume one to three existing notes and export every unit
// through two PUBLIC withdrawal lanes. No commitment is appended, no change
// note is made, and no output ciphertext is required. Sender/amount privacy
// at a public withdrawal is necessarily weaker than an inner transfer.
template PrivateExitV8(depth) {
    signal input root;
    signal input nullifiers[3];
    signal input publicContext;

    signal input inAsset[3];
    signal input active[3];
    signal input inAmount[3];
    signal input ownerSecret[3];
    signal input inNonce[3];
    signal input dummySecret[3];
    signal input siblings[3][depth];
    signal input pathBits[3][depth];
    // 0=idle, 1=SOL, 2=legacy SPL. Both lanes are withdrawals.
    signal input laneKind[2];
    signal input laneAsset[2];
    signal input laneAmount[2];
    signal input laneAddress[2][2];
    signal input submitter[2];
    signal input programDomain[2];

    component inRange[3];
    component inZero[3];
    component dummyZero[3];
    component ownerHash[3];
    component inputNote[3];
    component realNullifier[3];
    component dummyNullifier[3];
    signal nodes[3][depth + 1];
    signal left[3][depth];
    signal right[3][depth];
    component parents[3][depth];

    for (var j = 0; j < 3; j++) {
        active[j] * (active[j] - 1) === 0;
        inRange[j] = Num2Bits(64);
        inRange[j].in <== inAmount[j];
        (1 - active[j]) * inAmount[j] === 0;
        inZero[j] = IsZero();
        inZero[j].in <== inAmount[j];
        active[j] * inZero[j].out === 0;
        dummyZero[j] = IsZero();
        dummyZero[j].in <== dummySecret[j];
        (1 - active[j]) * dummyZero[j].out === 0;

        ownerHash[j] = Poseidon(2);
        ownerHash[j].inputs[0] <== 31;
        ownerHash[j].inputs[1] <== ownerSecret[j];
        inputNote[j] = Poseidon(5);
        inputNote[j].inputs[0] <== 11;
        inputNote[j].inputs[1] <== inAsset[j];
        inputNote[j].inputs[2] <== inAmount[j];
        inputNote[j].inputs[3] <== ownerHash[j].out;
        inputNote[j].inputs[4] <== inNonce[j];
        realNullifier[j] = Poseidon(3);
        realNullifier[j].inputs[0] <== 21;
        realNullifier[j].inputs[1] <== ownerSecret[j];
        realNullifier[j].inputs[2] <== inputNote[j].out;
        dummyNullifier[j] = Poseidon(3);
        dummyNullifier[j].inputs[0] <== 71;
        dummyNullifier[j].inputs[1] <== dummySecret[j];
        dummyNullifier[j].inputs[2] <== j + 1;
        nullifiers[j] === dummyNullifier[j].out
            + active[j] * (realNullifier[j].out - dummyNullifier[j].out);

        nodes[j][0] <== inputNote[j].out;
        for (var k = 0; k < depth; k++) {
            pathBits[j][k] * (pathBits[j][k] - 1) === 0;
            left[j][k] <== nodes[j][k]
                + pathBits[j][k] * (siblings[j][k] - nodes[j][k]);
            right[j][k] <== siblings[j][k]
                + pathBits[j][k] * (nodes[j][k] - siblings[j][k]);
            parents[j][k] = Poseidon(2);
            parents[j][k].inputs[0] <== left[j][k];
            parents[j][k].inputs[1] <== right[j][k];
            nodes[j][k + 1] <== parents[j][k].out;
        }
        active[j] * (nodes[j][depth] - root) === 0;
    }

    component same01 = IsZero();
    component same02 = IsZero();
    component same12 = IsZero();
    same01.in <== nullifiers[0] - nullifiers[1];
    same02.in <== nullifiers[0] - nullifiers[2];
    same12.in <== nullifiers[1] - nullifiers[2];
    same01.out === 0;
    same02.out === 0;
    same12.out === 0;

    component kindRange[2];
    component kindInvalid[2];
    component kindIdle[2];
    component kindSol[2];
    component kindSpl[2];
    component laneAssetZero[2];
    component laneRange[2];
    component laneZero[2];
    component addressRange[2][2];
    component submitterRange[2];
    component programRange[2];
    component laneDigest[2];
    for (var lane = 0; lane < 2; lane++) {
        kindRange[lane] = Num2Bits(2);
        kindRange[lane].in <== laneKind[lane];
        kindInvalid[lane] = IsEqual();
        kindInvalid[lane].in[0] <== laneKind[lane];
        kindInvalid[lane].in[1] <== 3;
        kindInvalid[lane].out === 0;
        kindIdle[lane] = IsZero();
        kindIdle[lane].in <== laneKind[lane];
        kindSol[lane] = IsEqual();
        kindSol[lane].in[0] <== laneKind[lane];
        kindSol[lane].in[1] <== 1;
        kindSpl[lane] = IsEqual();
        kindSpl[lane].in[0] <== laneKind[lane];
        kindSpl[lane].in[1] <== 2;
        laneAssetZero[lane] = IsZero();
        laneAssetZero[lane].in <== laneAsset[lane];
        kindSpl[lane].out * laneAssetZero[lane].out === 0;
        laneRange[lane] = Num2Bits(64);
        laneRange[lane].in <== laneAmount[lane];
        laneZero[lane] = IsZero();
        laneZero[lane].in <== laneAmount[lane];
        kindIdle[lane].out * laneAmount[lane] === 0;
        kindIdle[lane].out * laneAsset[lane] === 0;
        kindSol[lane].out * laneAsset[lane] === 0;
        (1 - kindIdle[lane].out) * laneZero[lane].out === 0;
        for (var limb = 0; limb < 2; limb++) {
            addressRange[lane][limb] = Num2Bits(128);
            addressRange[lane][limb].in <== laneAddress[lane][limb];
        }
        laneDigest[lane] = Poseidon(6);
        laneDigest[lane].inputs[0] <== 81;
        laneDigest[lane].inputs[1] <== laneKind[lane];
        laneDigest[lane].inputs[2] <== laneAsset[lane];
        laneDigest[lane].inputs[3] <== laneAmount[lane];
        laneDigest[lane].inputs[4] <== laneAddress[lane][0];
        laneDigest[lane].inputs[5] <== laneAddress[lane][1];
    }
    component bindContext = Poseidon(7);
    bindContext.inputs[0] <== 84;
    for (var limb = 0; limb < 2; limb++) {
        programRange[limb] = Num2Bits(128);
        programRange[limb].in <== programDomain[limb];
        bindContext.inputs[limb + 1] <== programDomain[limb];
        submitterRange[limb] = Num2Bits(128);
        submitterRange[limb].in <== submitter[limb];
        bindContext.inputs[limb + 3] <== submitter[limb];
    }
    for (var lane = 0; lane < 2; lane++) bindContext.inputs[lane + 5] <== laneDigest[lane].out;
    publicContext === bindContext.out;

    // Every asset present among either inputs or lanes gets its own balance
    // equality. Credits sum at most three u64 values; debits sum at most two.
    // Both are far below Fr, so modular wrap cannot manufacture funds.
    signal asset[5];
    signal amount[5];
    for (var j = 0; j < 3; j++) {
        asset[j] <== inAsset[j];
        amount[j] <== inAmount[j];
    }
    for (var j = 0; j < 2; j++) {
        asset[j + 3] <== laneAsset[j];
        amount[j + 3] <== laneAmount[j];
    }
    component equalAsset[5][5];
    signal selectedAmount[5][5];
    for (var a = 0; a < 5; a++) {
        for (var b = 0; b < 5; b++) {
            equalAsset[a][b] = IsEqual();
            equalAsset[a][b].in[0] <== asset[a];
            equalAsset[a][b].in[1] <== asset[b];
            selectedAmount[a][b] <== equalAsset[a][b].out * amount[b];
        }
        selectedAmount[a][0] + selectedAmount[a][1] + selectedAmount[a][2]
            === selectedAmount[a][3] + selectedAmount[a][4];
    }
    component noInputValue = IsZero();
    noInputValue.in <== inAmount[0] + inAmount[1] + inAmount[2];
    noInputValue.out === 0;
}

component main {public [root, nullifiers, publicContext]} = PrivateExitV8(32);
