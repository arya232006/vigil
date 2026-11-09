"use client";

import { Show, SignInButton, UserButton } from "@clerk/nextjs";

/** "Sign in" for guests, the profile menu for signed-in users. */
export function AccountControls() {
  return (
    <>
      <Show when="signed-out">
        <SignInButton>
          <button type="button" className="tile cursor-pointer">Sign in</button>
        </SignInButton>
      </Show>
      <Show when="signed-in">
        <span className="flex items-center px-1.5">
          <UserButton />
        </span>
      </Show>
    </>
  );
}
