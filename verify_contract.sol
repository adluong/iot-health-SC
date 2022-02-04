// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G2Point a;
        Pairing.G1Point b;
        Pairing.G2Point c;
        Pairing.G2Point gamma;
        Pairing.G1Point gamma_beta_1;
        Pairing.G2Point gamma_beta_2;
        Pairing.G2Point z;
        Pairing.G1Point[] ic;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G1Point a_p;
        Pairing.G2Point b;
        Pairing.G1Point b_p;
        Pairing.G1Point c;
        Pairing.G1Point c_p;
        Pairing.G1Point h;
        Pairing.G1Point k;
    }
//============================================
    struct metaData{
        uint256 ID;
        uint256 m;
    }
    
    struct Pseudonyms {
        address adr;            //address of pseudonym
        uint256 pi;             //parameter
        uint256[] devices;      //devices list
    }
    
    uint cnt = 0;
    uint dv_cnt = 0;
    Pseudonyms[1000] pseu;
    metaData[10000] dv;
    
    function checkPar(uint[] memory inputVal) internal returns (bool){
        uint i;
        uint c = inputVal[0];
        for(i=0; i<=cnt; i++){
            if(c == pseu[i].pi)
                return false;
        }
        store(c);
        return true;
    }
      
    function store(uint p) private{
        pseu[cnt].adr = msg.sender;
        pseu[cnt].pi = p;
        cnt++;
    }
    
    function addDevices(uint256 m,uint256 id) public returns (bool){
        uint i;
        for(i=0;i<=cnt;i++){
            if(msg.sender == pseu[i].adr){
                pseu[i].devices.push(m);
                dv[dv_cnt].m = m;
                dv[dv_cnt].ID = id;
                dv_cnt++;
                return true;
            }
        }
        return false;
    }

    function checkPseu() private returns (bool){
        uint i;
        for(i=0;i<=cnt;i++){
            if(msg.sender == pseu[i].adr) return true;
        }
        return false;
    }

    function removeDevices(uint256 m) public returns(bool){
        if(checkPseu()){
            uint i;
            uint j;
            for(i=0;i<cnt;i++){
                if(msg.sender == pseu[i].adr){
                    uint len = pseu[i].devices.length;
                     for(j=0;j<len;j++){
                         if(m == pseu[i].devices[j]){
                            delete(pseu[i].devices[j]);
                            pseu[i].devices[j] = pseu[i].devices[len-1];
                        }
                     }
                     for(j=0;j<dv_cnt;j++){
                         if(m == dv[j].m){
                             dv[j].m = 0;
                             dv[j].ID = 0;
                             dv[j]=dv[dv_cnt-1];
                             dv_cnt--;
                         }
                     }//end dv for
                     return true;
                }//end if
            }//end big for
        }
        return false;
    }
    
    metaData public qresult;

    function query(uint256 m) public returns (metaData memory){
        uint i;
        
        for(i=0;i<dv_cnt;i++){
            if(m == dv[i].m){
                qresult = dv[i];
                return qresult;
            }
        }
        qresult.m = 0; qresult.ID = 0;
        return qresult;
    }
//============================================
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.a = Pairing.G2Point([uint256(0x2c9cc6f64d27fe5dcbc55f98339834a46ac08cc23f34e772b96ae4b71314d578), uint256(0x254af4f7cce9c8ab5e3540434f8c9ff7bed91b775661fa3faf3337d1c758ee84)], [uint256(0x2bfea4845e2476e91078a926e633375248d07c2cfdc263699cd9dd891616e30d), uint256(0x1aaf8955db5178f1843530aaee9d3e13436be3da1c1538f504b1d35877a003c6)]);
        vk.b = Pairing.G1Point(uint256(0x040ed2c32a5ade5c32ee3aa801c8467ae88fafe91bb7d7b5928b08293b87fe88), uint256(0x0fc8b754296886c3db05b06125c6890fd886df2b0f2ba9fe6c1b11ea14931186));
        vk.c = Pairing.G2Point([uint256(0x0e6efebdcfe796fbef6cc7733f73a47d26b6accb725fe691f1350025ab2f6ef2), uint256(0x24fd24535fd36d5308e419d9a3ef93bbe66c6c610fcaf844d67826732e012a24)], [uint256(0x1459bc5aed04732ddb58a9f7e26807a4ee6961d98f5e24a0b421f7b6aa8c2e14), uint256(0x2af8a0f9dd66e7d00266140eb9f7481197ae9ad5a483fc745df26c0eb5676318)]);
        vk.gamma = Pairing.G2Point([uint256(0x1560b5101cb7b6db0847b832eed89b01c874f81c4c5f11f11a84954f29cb745e), uint256(0x079bbdff4288c466e7b37f45f9a6fcbb79f18ab4eceb1a0d408c5e800b24e8ee)], [uint256(0x20193a66026a67639a12107c4811b028fb00d98501c79cf3a259ac9f494efeee), uint256(0x176c5d24ab800e71b47a48eb0f94672b180b6ef79b2d44b43731d0665d0c275d)]);
        vk.gamma_beta_1 = Pairing.G1Point(uint256(0x05fe3b862926d414689b2630217a106f855993457f04b037f37694b9e1be5af5), uint256(0x08b6d8afbfa11eb2daffa290286112c4e76d73c366dd5611447323f827da8781));
        vk.gamma_beta_2 = Pairing.G2Point([uint256(0x0321774a9878715d6359f74a30f86ed7190831526aee7e5f84a5313834eb517b), uint256(0x007803db6d36f83ff8ecbe426e87728d879429a43d18bd4d033d9a43d0aa4727)], [uint256(0x0a5a58b93af4693c4a855dd4ea1540191c4191da88b2ecbd73ed53b06b4204d5), uint256(0x22c992e3fc755c6fddea4c8cef2b144aca88064a4f0cbad21260bd1f346a6393)]);
        vk.z = Pairing.G2Point([uint256(0x250e329da345f8cf60c5e0f84dad9415b77b74034bec3e9d1b8b6ed61a8e2ef6), uint256(0x08844c11d02fccd20d7bbda1c978487a11f1830dd6c85333c1a8c742472a988c)], [uint256(0x061b6f42376a94c770f3c28c7a2c339e7d0450c41a239bce4b595f1fcb58db67), uint256(0x04dd4662251c25be6a692ec3410063219df746e79cef2cb41f591506dd2770d6)]);
        vk.ic = new Pairing.G1Point[](2);
        vk.ic[0] = Pairing.G1Point(uint256(0x1e34f310dd2655d7d075c457dec3dc58b763fd9394faa66cbfcef45a3cd015d8), uint256(0x18fc804af0888730bb88f45263e83eb51af53683afe477c241d5507eced5e622));
        vk.ic[1] = Pairing.G1Point(uint256(0x20210357d28cbc333c7632bd914f9082f037daf129b9c3e67fa4332b312de26d), uint256(0x1b73e75515262114a3426a6816da5d76b8b8f6f71521dee734b2326cede2d94c));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.ic.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.ic[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.ic[0]);
        if (!Pairing.pairingProd2(proof.a, vk.a, Pairing.negate(proof.a_p), Pairing.P2())) return 1;
        if (!Pairing.pairingProd2(vk.b, proof.b, Pairing.negate(proof.b_p), Pairing.P2())) return 2;
        if (!Pairing.pairingProd2(proof.c, vk.c, Pairing.negate(proof.c_p), Pairing.P2())) return 3;
        if (!Pairing.pairingProd3(
            proof.k, vk.gamma,
            Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.a, proof.c))), vk.gamma_beta_2,
            Pairing.negate(vk.gamma_beta_1), proof.b
        )) return 4;
        if (!Pairing.pairingProd3(
                Pairing.addition(vk_x, proof.a), proof.b,
                Pairing.negate(proof.h), vk.z,
                Pairing.negate(proof.c), Pairing.P2()
        )) return 5;
        return 0;
    }
     function verifyTx(
            Proof memory proof, uint[1] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](1);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            if(checkPar(inputValues))
                return true;
            else
                return false;
        } else {
            return false;
        }
    }
}
