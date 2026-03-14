# Frontend Layout Guide

This page has a small set of layout rules. New sections should follow these instead of introducing one-off wrapper combinations.

## Canonical Containers

- `page-shell`
  - Use for the primary page-width wrapper.
  - Standard width: `max-width: 80rem`.
  - Standard horizontal padding: `1rem`, `1.5rem` from `sm`, `2rem` from `lg`.
- Modal shells
  - Keep modal width local to the modal component.
  - Use one width rule per modal (`max-w-md`, `max-w-2xl`, `max-w-4xl`, `max-w-6xl`) instead of nesting another page-width wrapper inside the modal body.
- Full-width bands
  - Keep them inside `page-shell` unless the section is intentionally edge-to-edge.
  - Prefer section-level spacing and borders over adding another max-width wrapper.

## Rules

- Do not repeat `mx-auto max-w-7xl px-4 sm:px-6 lg:px-8` inline. Use `page-shell`.
- Do not nest multiple page-width wrappers inside one another.
- Keep section spacing consistent before adding custom width rules.
- If a section needs a custom width, document why it is not using `page-shell`.

## Current Standard

- The main page shell in [`/Users/techmore/projects/NmapUI/templates/index.html`](/Users/techmore/projects/NmapUI/templates/index.html) is the canonical example.
- Follow this guide for future layout refactors tied to [#74](https://github.com/techmore/NmapUI/issues/74).
