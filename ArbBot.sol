// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.2 <=0.8.19;

// H6 atomic arbitrage bot — CSE 242 Fall 2026
// Buys a token where it's cheap and sells where it's dear in ONE transaction.
// Reverts unless it ends with >= minProfitWei more FAKEETH than it started.

interface ITokenExchange {
    function swapForEth(uint _amountERC20Token) external returns (uint);
    function swapForERC20Token() external payable returns (uint);
    function estimateSwapForEth(uint _amountERC20Token) external view returns (uint);
    function estimateSwapForERC20Token(uint _amountEth) external view returns (uint);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ArbBot {
    address public owner;

    event Arb(address indexed token, address exBuy, address exSell, uint ethIn, uint ethOut, int profit);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    receive() external payable {}
    function fund() external payable {}

    function checkArb(address exBuy, address exSell, uint ethIn)
        external view
        returns (uint tokMid, uint ethOut)
    {
        tokMid = ITokenExchange(exBuy).estimateSwapForERC20Token(ethIn);
        ethOut = ITokenExchange(exSell).estimateSwapForEth(tokMid);
    }

    function arb(
        address exBuy,
        address exSell,
        address token,
        uint ethIn,
        uint minProfitWei
    ) external onlyOwner returns (int profit) {
        uint startBal = address(this).balance;        // includes ethIn, already held here
        require(startBal >= ethIn, "insufficient FAKEETH");

        // leg 1: FAKEETH -> token on exBuy
        uint tokOut = ITokenExchange(exBuy).swapForERC20Token{value: ethIn}();
        require(tokOut > 0, "leg1 gave 0 token");

        // leg 2: token -> FAKEETH on exSell (approve EXACT amount only)
        require(IERC20(token).approve(exSell, tokOut), "approve failed");
        uint ethOut = ITokenExchange(exSell).swapForEth(tokOut);

        uint endBal = address(this).balance;           // startBal - ethIn + ethOut
        require(endBal >= startBal + minProfitWei, "unprofitable: reverting");

        profit = int(endBal) - int(startBal);
        emit Arb(token, exBuy, exSell, ethIn, ethOut, profit);
    }

    function withdrawEth(uint amount) external onlyOwner {
        (bool ok, ) = owner.call{value: amount}("");
        require(ok, "eth withdraw failed");
    }

    function withdrawAllEth() external onlyOwner {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "eth withdraw failed");
    }

    function rescueToken(address token) external onlyOwner {
        IERC20 t = IERC20(token);
        t.transfer(owner, t.balanceOf(address(this)));
    }
}