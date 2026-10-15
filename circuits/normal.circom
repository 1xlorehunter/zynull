pragma circom 2.2.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// One 3-input/4-output envelope for deposits, inner transfers, withdrawals
// and atomic mixed operations. Public balance edges remain public on Solana;
// the context binds their exact execution accounts and values to this proof.
template PrivateOperationV9(depth) {
    signal input root;
    signal input nullifiers[3];
    signal input outCommitments[4];
    signal input deliveryBinding;
    signal input publicContext;

    signal input inAsset[3];
    signal input active[3];
    signal input inAmount[3];
    signal input ownerSecret[3];
    signal input inNonce[3];
    signal input dummySecret[3];
    signal input siblings[3][depth];
    signal input pathBits[3][depth];
    signal input outAsset[4];
    signal input outAmount[4];
    signal input outOwnerPub[4];
    signal input outNonce[4];
    // The handler reads a public u64 fee from the packet and recomputes the
    // context. The SNARK binds that amount to the fourth native fee note.
    signal input feeAmount;
    signal input deliveryHash;

    // Deposit lanes 0,1; withdrawal lanes 2,3. 0=idle, 1=SOL, 2=SPL.
    signal input laneKind[4];
    signal input laneAsset[4];
    signal input laneAmount[4];
    signal input laneAddress[4][2];
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

    component outRange[4];
    component outputNote[4];
    for (var m = 0; m < 4; m++) {
        outRange[m] = Num2Bits(64);
        outRange[m].in <== outAmount[m];
        outputNote[m] = Poseidon(5);
        outputNote[m].inputs[0] <== 11;
        outputNote[m].inputs[1] <== outAsset[m];
        outputNote[m].inputs[2] <== outAmount[m];
        outputNote[m].inputs[3] <== outOwnerPub[m];
        outputNote[m].inputs[4] <== outNonce[m];
        outCommitments[m] === outputNote[m].out;
    }
    outAsset[3] === 0;
    // outRange[3] enforces u64 on this equal feeAmount as well.
    outAmount[3] === feeAmount;

    signal kindProduct[4];
    signal kindIdle[4];
    signal kindSol[4];
    signal kindSpl[4];
    component laneAssetZero[4];
    component laneRange[4];
    component laneZero[4];
    component addressRange[4][2];
    component submitterRange[2];
    component programRange[2];
    component laneDigest[4];
    for (var lane = 0; lane < 4; lane++) {
        // Over the prime field k(k-1)(k-2)=0 permits exactly 0,1,2.
        // Lagrange basis polynomials give the same three role flags, while
        // avoiding independent IsEqual checks of this already finite set.
        kindProduct[lane] <== laneKind[lane] * (laneKind[lane] - 1);
        kindProduct[lane] * (laneKind[lane] - 2) === 0;
        kindIdle[lane] <== (laneKind[lane] - 1) * (laneKind[lane] - 2) / 2;
        kindSol[lane] <== laneKind[lane] * (2 - laneKind[lane]);
        kindSpl[lane] <== kindProduct[lane] / 2;
        laneAssetZero[lane] = IsZero();
        laneAssetZero[lane].in <== laneAsset[lane];
        kindSpl[lane] * laneAssetZero[lane].out === 0;
        laneRange[lane] = Num2Bits(64);
        laneRange[lane].in <== laneAmount[lane];
        laneZero[lane] = IsZero();
        laneZero[lane].in <== laneAmount[lane];
        kindIdle[lane] * laneAmount[lane] === 0;
        kindIdle[lane] * laneAsset[lane] === 0;
        kindSol[lane] * laneAsset[lane] === 0;
        (1 - kindIdle[lane]) * laneZero[lane].out === 0;
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
    component bindContext = Poseidon(9);
    bindContext.inputs[0] <== 82;
    for (var limb = 0; limb < 2; limb++) {
        programRange[limb] = Num2Bits(128);
        programRange[limb].in <== programDomain[limb];
        bindContext.inputs[limb + 1] <== programDomain[limb];
        submitterRange[limb] = Num2Bits(128);
        submitterRange[limb].in <== submitter[limb];
        bindContext.inputs[limb + 3] <== submitter[limb];
    }
    for (var lane = 0; lane < 4; lane++) {
        bindContext.inputs[lane + 5] <== laneDigest[lane].out;
    }
    component bindFeeContext = Poseidon(3);
    bindFeeContext.inputs[0] <== 91;
    bindFeeContext.inputs[1] <== bindContext.out;
    bindFeeContext.inputs[2] <== feeAmount;
    publicContext === bindFeeContext.out;

    // Slots 0..4 credit and 5..10 debit. Checking the balance for the
    // asset of every slot covers every asset in the operation, including
    // assets appearing only in outputs. Each side sums at most six u64
    // amounts; no field wraparound can manufacture value.
    signal asset[11];
    signal amount[11];
    for (var j = 0; j < 3; j++) {
        asset[j] <== inAsset[j];
        amount[j] <== inAmount[j];
    }
    for (var j = 0; j < 4; j++) {
        asset[j + 5] <== outAsset[j];
        amount[j + 5] <== outAmount[j];
    }
    for (var j = 0; j < 2; j++) {
        asset[j + 3] <== laneAsset[j];
        amount[j + 3] <== laneAmount[j];
        asset[j + 9] <== laneAsset[j + 2];
        amount[j + 9] <== laneAmount[j + 2];
    }
    component equalAsset[11][11];
    signal sameAsset[11][11];
    signal selectedAmount[11][11];
    for (var a = 0; a < 11; a++) {
        for (var b = 0; b < 11; b++) {
            if (a < b) {
                equalAsset[a][b] = IsEqual();
                equalAsset[a][b].in[0] <== asset[a];
                equalAsset[a][b].in[1] <== asset[b];
                sameAsset[a][b] <== equalAsset[a][b].out;
            } else if (a == b) {
                sameAsset[a][b] <== 1;
            } else {
                // Equality is symmetric; compute it once for each pair.
                sameAsset[a][b] <== sameAsset[b][a];
            }
            selectedAmount[a][b] <== sameAsset[a][b] * amount[b];
        }
        selectedAmount[a][0] + selectedAmount[a][1]
            + selectedAmount[a][2] + selectedAmount[a][3]
            + selectedAmount[a][4] === selectedAmount[a][5]
            + selectedAmount[a][6] + selectedAmount[a][7]
            + selectedAmount[a][8] + selectedAmount[a][9]
            + selectedAmount[a][10];
    }
    component noInflow = IsZero();
    noInflow.in <== inAmount[0] + inAmount[1] + inAmount[2]
        + laneAmount[0] + laneAmount[1];
    noInflow.out === 0;

    component bindDelivery = Poseidon(5);
    bindDelivery.inputs[0] <== outCommitments[0];
    bindDelivery.inputs[1] <== outCommitments[1];
    bindDelivery.inputs[2] <== outCommitments[2];
    bindDelivery.inputs[3] <== outCommitments[3];
    bindDelivery.inputs[4] <== deliveryHash;
    deliveryBinding === bindDelivery.out;
}

component main {public [root, nullifiers, outCommitments,
    deliveryBinding, publicContext]} = PrivateOperationV9(32);
