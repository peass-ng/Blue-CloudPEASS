import assert from "node:assert/strict";
import { test } from "node:test";
import { explainPrivescCondition } from "../src/privescCondition.ts";

test("unknown selector and guardrail keys become readable reasons", () => {
  assert.equal(
    explainPrivescCondition("selector_aws_challenge_fact_not_evaluated"),
    "The AWS challenge fact target selector could not be verified from this snapshot.",
  );
  assert.equal(
    explainPrivescCondition("scp_not_evaluated"),
    "SCP was not evaluated.",
  );
  assert.equal(
    explainPrivescCondition("blocker_permissions_boundary_possibly_enforced"),
    "Permissions boundary may block this path.",
  );
});

test("authored technique condition takes precedence over its machine key", () => {
  assert.equal(
    explainPrivescCondition("exact_verified_prerequisites", "The actual credential owner must be verified."),
    "The actual credential owner must be verified.",
  );
  assert.equal(explainPrivescCondition("passrole_condition_key"), "PassRole condition key.");
});
