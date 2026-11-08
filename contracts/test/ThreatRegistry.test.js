const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatRegistry", () => {
  const reportHash = ethers.sha256(ethers.toUtf8Bytes('{"risk_level":"high_risk"}'));
  const otherHash = ethers.sha256(ethers.toUtf8Bytes('{"risk_level":"low_risk"}'));
  const indicatorHash = ethers.keccak256(ethers.toUtf8Bytes("evil.example"));
  let registry, alice;

  beforeEach(async () => {
    [, alice] = await ethers.getSigners();
    registry = await (await ethers.getContractFactory("ThreatRegistry")).deploy();
  });

  it("starts empty", async () => {
    expect(await registry.count()).to.equal(0n);
  });

  it("stores the commitment and emits it", async () => {
    await expect(registry.connect(alice).submit(reportHash, indicatorHash))
      .to.emit(registry, "ReportSubmitted")
      .withArgs(0n, reportHash, indicatorHash, alice.address);

    const stored = await registry.reports(0);
    expect(stored.reporter).to.equal(alice.address);
    expect(stored.reportHash).to.equal(reportHash);
    expect(stored.indicatorHash).to.equal(indicatorHash);
    expect(stored.timestamp).to.be.greaterThan(0n);
    expect(await registry.count()).to.equal(1n);
  });

  it("assigns sequential ids", async () => {
    await registry.submit(reportHash, indicatorHash);
    await expect(registry.submit(otherHash, indicatorHash))
      .to.emit(registry, "ReportSubmitted")
      .withArgs(1n, otherHash, indicatorHash, (await ethers.getSigners())[0].address);
  });

  it("verifies only the exact committed hash", async () => {
    await registry.submit(reportHash, indicatorHash);
    expect(await registry.verify(0, reportHash)).to.equal(true);
    expect(await registry.verify(0, otherHash)).to.equal(false);
  });

  it("reverts when verifying an unknown id", async () => {
    await expect(registry.verify(0, reportHash)).to.be.revertedWithPanic(0x32);
  });

  it("finds a domain's reports by the indexed indicator hash", async () => {
    await registry.submit(reportHash, indicatorHash);
    await registry.submit(otherHash, ethers.keccak256(ethers.toUtf8Bytes("other.example")));
    const logs = await registry.queryFilter(registry.filters.ReportSubmitted(null, null, indicatorHash));
    expect(logs.map((l) => l.args.id)).to.deep.equal([0n]);
  });
});
