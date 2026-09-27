# iNode Modern

<!-- impeccable:product-schema 1 -->

## Platform

Linux desktop — native Qt 6 / PySide6, Fedora KDE / Wayland.

Impeccable's web/ios/android/adaptive taxonomy does not describe this existing
desktop application. Native Qt controls, keyboard navigation, desktop palette
changes and display scaling are the applicable platform conventions.

## Users

Users of the existing H3C campus wired authentication service on Fedora KDE.
The repository's verified deployment context is Southwestern University of
Finance and Economics. Broader campus compatibility is not established.

## Product Purpose

Enter campus credentials, connect, understand the actual authentication state,
recover from a failed attempt, and disconnect when wanted. Closing the window
exits the frontend without implicitly ending authentication.

## Positioning

A native desktop frontend for the existing H3C authentication engine, retaining
its validated authentication semantics and the deployed Broker boundary.

## Operating Context

An ordinary user opens the application from KDE. System services own the
authentication engine. The GUI selects a wired interface and requests actions;
it never acquires administrative privileges. Authentication and an assigned
network address are distinct facts; neither proves Internet reachability.

## Capabilities and Constraints

- Preserve connect, disconnect, status refresh, full credential input, wired
  interface selection and activation of an existing DHCP connection.
- Preserve exact username and password input and established validation.
- Optional remembered credentials use the existing KWallet/Secret Service
  implementation. Secure-storage failure has no plaintext fallback.
- Backend, Broker, protocol, services, firewall, isolation and rollback are
  outside this redesign's modification boundary.
- GUI layout and presentation structure may be replaced completely. Prefer
  the existing PySide6 dependency and avoid additional heavy dependencies.

## Brand Commitments

Keep the iNode Modern name and existing application identity/icon. Chinese is
the existing interface language. No additional visual constraints were given.

## Evidence on Hand

The desktop implementation, tests/test_desktop_*.py and the synthetic Qt state
renderer provide inspectable behavior. Historical screenshots show the incumbent
interface; they do not define the replacement design system.

## Product Principles

- Make the current state and the next available action clear together.
- Report authentication evidence truthfully, including uncertainty and failure.
- Protect credentials and keep routine use within ordinary-user permissions.
- Preserve the production boundary while improving the desktop experience.

## Open Decisions

Public beta targets Fedora 44 x86_64 and Southwestern University of Finance and Economics users. Other distributions and campuses are not validated.
