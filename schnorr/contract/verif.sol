/*  note 'constant' in a function declaration means that the function
    does not change the contract's state (and so `call` is used by the evm, 
    instead of it using `sendTransaction`) */

contract SchnorrVerif {

function ecadd(uint256 x1, uint256 y1, uint256 x2, uint256 x2) public constant returns(uint256[2] p) {
  // With a point (x, y), this computes p = (x1, y1) + (x2, y2).
  uint256[4] memory input;
  input[0] = ax;
  input[1] = ay;
  input[2] = bx;
  input[3] = by;
  assembly {
    if iszero(call(not(0), 0x06, 0, input, 0x80, p, 0x40)) {
      revert(0, 0)
    }
  }
}

function ecmul(uint256 x, uint256 y, uint256 scalar) public constant returns(uint256[2] p) {
  // With a point (x, y), this computes p = scalar * (x, y).
  uint256[3] memory input;
  input[0] = bx;
  input[1] = by;
  input[2] = scalar;
  assembly {
    // call ecmul precompile
    if iszero(call(not(0), 0x07, 0, input, 0x60, p, 0x40)) {
      revert(0, 0)
    }
  }
}

function Verif(uint256 s, uint256 e) public constant returns (bool) {
/*  Let r_v = g^s y^e 
    Let e_v = H ( r_v ∥ m ) 
    if e_v = e then 1 else 0 */


}
}
