// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ThreatRegistry
/// @notice Append-only commitments to ThreatScope reports. Only hashes are stored: never a URL, message or email.
/// @dev A record proves a report's integrity and history, not that its conclusions are true.
contract ThreatRegistry {
    struct Report {
        address reporter;
        uint64 timestamp;
        bytes32 reportHash;     // sha256 of the report's canonical JSON (GET /api/reports/{id}/canonical)
        bytes32 indicatorHash;  // keccak256 of the normalised domain; zero when the report has no domain
    }

    Report[] public reports;

    event ReportSubmitted(uint256 indexed id, bytes32 reportHash,
                          bytes32 indexed indicatorHash, address reporter);

    function submit(bytes32 reportHash, bytes32 indicatorHash)
        external returns (uint256 id)
    {
        id = reports.length;
        reports.push(Report(msg.sender, uint64(block.timestamp),
                            reportHash, indicatorHash));
        emit ReportSubmitted(id, reportHash, indicatorHash, msg.sender);
    }

    function verify(uint256 id, bytes32 h) external view returns (bool) {
        return reports[id].reportHash == h;
    }

    function count() external view returns (uint256) { return reports.length; }
}
