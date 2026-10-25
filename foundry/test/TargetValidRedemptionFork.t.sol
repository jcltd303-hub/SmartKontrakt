// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";

interface IRedeemTarget {
  enum StorageProtocol { INVALID, NONE, ARWEAVE, IPFS }
  enum ValidationType { INVALID, CONTRACT, RANGE, MERKLE_TREE, ANY }
  enum TokenSpec { INVALID, ERC721, ERC1155 }
  enum BurnSpec { NONE, MANIFOLD, OPENZEPPELIN }
  struct BurnItem { ValidationType validationType; address contractAddress; TokenSpec tokenSpec; BurnSpec burnSpec; uint72 amount; uint256 minTokenId; uint256 maxTokenId; bytes32 merkleRoot; }
  struct BurnGroup { uint256 requiredCount; BurnItem[] items; }
  struct Parameters { address payable paymentReceiver; StorageProtocol storageProtocol; uint16 redeemAmount; uint32 totalSupply; uint48 startDate; uint48 endDate; uint160 cost; string location; BurnGroup[] burnSet; }
  struct BurnToken { uint48 groupIndex; uint48 itemIndex; address contractAddress; uint256 id; bytes32[] merkleProof; }
  function initializeBurnRedeem(address,uint256,Parameters calldata,bool) external;
  function burnRedeem(address,uint256,uint32,BurnToken[] calldata) external payable;
}

contract ForkMockCreator {
  mapping(address => bool) public admins;
  uint256 public minted;
  mapping(address => uint256) public balances;
  constructor(address a) { admins[a]=true; }
  function VERSION() external pure returns (uint256) { return 3; }
  function isAdmin(address a) external view returns(bool) { return admins[a]; }
  function mintExtension(address to, uint80) external returns(uint256) { balances[to]++; return ++minted; }
  function mintExtensionBatch(address to, uint80[] calldata data) external returns(uint256[] memory ids) {
    ids = new uint256[](data.length);
    for(uint i=0;i<data.length;i++) { balances[to]++; ids[i]=++minted; }
  }
}

contract ForkMock1155 {
  mapping(address=>mapping(uint256=>uint256)) public balanceOf;
  bool public reenter;
  address public redeem;
  bytes public attempted;
  constructor(address t) { redeem=t; }
  function mint(address to,uint256 id,uint256 amount) external { balanceOf[to][id]+=amount; }
  function burn(address from,uint256 id,uint256 amount) external {
    require(balanceOf[from][id] >= amount, "insufficient tokens");
    balanceOf[from][id] -= amount;
    if(reenter) { (bool ok,) = redeem.call(attempted); require(!ok, "reentry unexpectedly succeeded"); }
  }
  function setReentry(bytes calldata data) external { reenter=true; attempted=data; }
}

contract TargetValidRedemptionForkTest is Test {
  IRedeemTarget target;
  ForkMockCreator creator;
  ForkMock1155 token;
  address outsider=address(0xBEEF1234);
  uint256 constant INSTANCE=9041226;
  function setUp() public {
    target=IRedeemTarget(vm.envAddress("POC_TARGET"));
    creator=new ForkMockCreator(address(this));
    token=new ForkMock1155(address(target));
    IRedeemTarget.BurnItem[] memory items=new IRedeemTarget.BurnItem[](1);
    items[0]=IRedeemTarget.BurnItem(IRedeemTarget.ValidationType.CONTRACT,address(token),IRedeemTarget.TokenSpec.ERC1155,IRedeemTarget.BurnSpec.OPENZEPPELIN,1,0,0,bytes32(0));
    IRedeemTarget.BurnGroup[] memory groups=new IRedeemTarget.BurnGroup[](1);
    groups[0]=IRedeemTarget.BurnGroup(1,items);
    IRedeemTarget.Parameters memory p=IRedeemTarget.Parameters(payable(address(this)),IRedeemTarget.StorageProtocol.NONE,1,2,0,0,0,"local-fork",groups);
    target.initializeBurnRedeem(address(creator),INSTANCE,p,false);
    token.mint(outsider,1,4);
    vm.deal(outsider,1 ether);
  }
  function _burns(uint256 n) internal view returns(IRedeemTarget.BurnToken[] memory arr) {
    arr=new IRedeemTarget.BurnToken[](n);
    for(uint256 i;i<n;i++) arr[i]=IRedeemTarget.BurnToken(0,0,address(token),1,new bytes32[](0));
  }
  function test_validRedemptionBurnsAndMintsOne() public {
    vm.prank(outsider);
    target.burnRedeem{value:990000000000000}(address(creator),INSTANCE,1,_burns(1));
    assertEq(creator.balances(outsider),1);
    assertEq(token.balanceOf(outsider,1),3);
  }
  function test_insufficientPaymentRevertsAtomically() public {
    vm.prank(outsider);
    vm.expectRevert();
    target.burnRedeem(address(creator),INSTANCE,1,_burns(1));
    assertEq(creator.balances(outsider),0);
    assertEq(token.balanceOf(outsider,1),4);
  }
  function test_supplyCapCannotBeExceeded() public {
    vm.startPrank(outsider);
    target.burnRedeem{value:990000000000000}(address(creator),INSTANCE,1,_burns(1));
    target.burnRedeem{value:990000000000000}(address(creator),INSTANCE,1,_burns(1));
    vm.expectRevert();
    target.burnRedeem{value:990000000000000}(address(creator),INSTANCE,1,_burns(1));
    vm.stopPrank();
    assertEq(creator.balances(outsider),2);
    assertEq(token.balanceOf(outsider,1),2);
  }
  function test_duplicateBurnInputsCannotMintExtra() public {
    vm.prank(outsider);
    vm.expectRevert();
    target.burnRedeem{value:990000000000000}(address(creator),INSTANCE,1,_burns(2));
    assertEq(creator.balances(outsider),0);
    assertEq(token.balanceOf(outsider,1),4);
  }
  function test_externalBurnReentrancyCannotDoubleMint() public {
    bytes memory retry=abi.encodeWithSelector(IRedeemTarget.burnRedeem.selector,address(creator),INSTANCE,uint32(1),_burns(1));
    token.setReentry(retry);
    vm.prank(outsider);
    target.burnRedeem{value:990000000000000}(address(creator),INSTANCE,1,_burns(1));
    assertEq(creator.balances(outsider),1);
    assertEq(token.balanceOf(outsider,1),3);
  }
}
