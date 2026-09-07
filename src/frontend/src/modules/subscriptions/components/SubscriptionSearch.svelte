<script lang="ts">
  import { getContext } from "svelte";

  import { t } from "../../../data/locale.svelte";
  import { SUBSCRIPTIONS_STORE_CONTEXT, type SubscriptionsStore } from "../subscriptions.svelte";

  import { Search } from "../../../components/ui/icons";

  const store = getContext<SubscriptionsStore>(SUBSCRIPTIONS_STORE_CONTEXT);
  if (!store) {
    throw new Error("SubscriptionsStore context is missing");
  }

  let inputRef: HTMLInputElement;

  function handleSearchShortcut(event: KeyboardEvent) {
    if (
      event.defaultPrevented ||
      event.altKey ||
      event.shiftKey ||
      !(event.metaKey || event.ctrlKey) ||
      (event.code !== "KeyF" && event.key.toLowerCase() !== "f") ||
      !inputRef?.getClientRects().length
    )
      return;

    event.preventDefault();
    inputRef.focus();
    inputRef.select();
  }

  function handleContainerClick() {
    inputRef?.focus();
  }

  function handleContainerPointerDown(event: PointerEvent) {
    const target = event.target;
    if (target instanceof HTMLInputElement) return;

    event.preventDefault();
    inputRef?.focus();
  }
</script>

<svelte:window onkeydown={handleSearchShortcut} />

<div class="subscription-controls-search">
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="search-container"
    onclick={handleContainerClick}
    onpointerdown={handleContainerPointerDown}
  >
    <span class="icon-wrapper">
      <Search />
    </span>

    <div class="input-wrapper">
      <input
        bind:this={inputRef}
        type="search"
        class="search-input"
        placeholder={t("Search subscriptions and rules...")}
        bind:value={store.searchValue}
      />
    </div>
  </div>
</div>

<style>
  .subscription-controls-search {
    display: flex;
    align-items: center;
    flex: 0 1 auto;
    transition: flex-grow 0.3s ease;
    min-width: 0;
  }

  .search-container {
    --search-icon-size: 1.5rem;
    --search-collapsed-width: calc(var(--search-icon-size) + 1.2rem + 2px);
    background-color: var(--bg-light);
    padding: 0.6rem;
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    color: var(--text-2);
    font: 400 1rem var(--font);
    display: flex;
    align-items: center;
    cursor: pointer;
    box-sizing: border-box;
    white-space: nowrap;
    width: auto;
    transition:
      background-color 0.1s ease-in-out,
      border-color 0.1s ease-in-out,
      box-shadow 0.1s ease-in-out,
      color 0.1s ease-in-out,
      width 0.3s cubic-bezier(0.25, 1, 0.5, 1);
  }

  .search-container:hover {
    background-color: var(--bg-light-extra);
    color: var(--text);
  }

  .search-container:focus-within,
  .search-container:has(.search-input:not(:placeholder-shown)) {
    cursor: text;
    background-color: var(--bg-light);
    color: var(--text);
    border-color: var(--accent);
    max-width: 100%;
    box-shadow:
      0 0 0 1px color-mix(in oklab, var(--accent) 45%, transparent),
      0 6px 18px -14px color-mix(in oklab, var(--accent) 35%, transparent);
  }

  .icon-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .icon-wrapper :global(svg) {
    width: var(--search-icon-size);
    height: var(--search-icon-size);
  }

  .input-wrapper {
    width: min(700px, 50vw);
    margin-left: 0.3rem;
    overflow: hidden;
    transition:
      width 0.3s cubic-bezier(0.25, 1, 0.5, 1),
      margin-left 0.3s cubic-bezier(0.25, 1, 0.5, 1);
  }

  .search-container:focus-within .input-wrapper,
  .search-container:has(.search-input:not(:placeholder-shown)) .input-wrapper {
    margin-left: 0.3rem;
    width: min(700px, 50vw);
  }

  .search-input {
    appearance: none;
    border: none;
    background: transparent;
    outline: none;
    margin: 0;
    padding: 0;
    font: inherit;
    color: inherit;
    width: 100%;
    opacity: 1;
    transition: opacity 0.2s ease;
  }

  .search-input::-webkit-search-cancel-button {
    cursor: pointer;
  }

  .search-container:focus-within .search-input,
  .search-container:has(.search-input:not(:placeholder-shown)) .search-input {
    opacity: 1;
  }

  @media (max-width: 570px) {
    .input-wrapper {
      width: 0;
      margin-left: 0;
    }

    .search-input {
      opacity: 0;
    }

    .subscription-controls-search {
      flex: 1 1 auto;
      min-width: 0;
    }

    .search-container {
      --search-icon-size: 22px;
      --search-collapsed-width: calc(var(--search-icon-size) + 1.2rem + 2px);
      width: var(--search-collapsed-width);
      height: var(--search-collapsed-width);
      min-height: var(--search-collapsed-width);
      min-width: 0;
      padding: 0.6rem;
    }

    .search-container:focus-within,
    .search-container:has(.search-input:not(:placeholder-shown)) {
      width: 100%;
    }

    .search-container:focus-within .input-wrapper,
    .search-container:has(.search-input:not(:placeholder-shown)) .input-wrapper {
      width: 100%;
    }
  }
</style>
