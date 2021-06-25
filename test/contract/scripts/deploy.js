const hre = require("hardhat");

async function main() {
    // await hre.run('compile');
    // We get the contract to deploy
    const GLDToken = await hre.ethers.getContractFactory("GLDToken");
    const token = await GLDToken.deploy();
    await token.deployed();
    console.log("GLDToken deployed to:", token.address, token.deployTransaction.hash);
}
// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });