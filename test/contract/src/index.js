const fastify = require('fastify')({ logger: true });
const hre = require("hardhat");

// readiness check
fastify.get('/v1/healthz', async (req, reply) => {
    reply
        .code(200)
        .header('Content-Type', 'application/json; charset=utf-8')
        .send({ success: true })
});

fastify.get('/v1/deployContract', async (req, reply) => {
    const GLDToken = await hre.ethers.getContractFactory("GLDToken");
    const token = await GLDToken.deploy();
    await token.deployed();

    return {
        address: token.address,
        txHash: token.deployTransaction.hash,
        blockNumber: token.deployTransaction.blockNumber,
        blockHash: token.deployTransaction.blockHash,
    }
});

fastify.get('/v1/sendEth', async (req, reply) => {
    const to = req.query.to;
    const value = req.query.value;

    const [owner] = await hre.ethers.getSigners();
    const tx = await owner.sendTransaction({
        to,
        value: hre.ethers.utils.parseEther(value)
    });
    await tx.wait(1)

    // console.log(tx);
    // const coinbaseBalance = await hre.ethers.provider.getBalance(owner.address);
    // const receiverBalance = await hre.ethers.provider.getBalance(to);
    // console.log(coinbaseBalance.toString(), receiverBalance.toString());

    return {
        from: tx.from,
        to: tx.to,
        //value: tx.value.toString(),
        txHash: tx.hash,
        blockNumber: tx.blockNumber,
        blockHash: tx.blockHash,
    }
});

async function main() {
    try {
        await fastify.listen(3000, '0.0.0.0');
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
}

main();