<script lang="ts">
  import { onDestroy, onMount, setContext, tick } from "svelte";

  import PageControls from "../../components/layout/PageControls.svelte";
  import Placeholder from "../../components/ui/Placeholder.svelte";
  import { t } from "../../data/locale.svelte";
  import GroupPanel from "./components/GroupPanel.svelte";
  import Search from "./components/Search.svelte";
  import ImportConfigDialog from "./dialogs/ImportConfigDialog.svelte";
  import ImportRulesDialog from "./dialogs/ImportRulesDialog.svelte";
  import {
    GROUPS_STORE_CONTEXT,
    GroupsStore,
    type GroupDragData,
    type GroupDropSlotData,
  } from "./groups.svelte";

  import { droppable } from "../../lib/dnd";
  import { parseConfig, type Group, type Rule } from "../../types";
  import { toast } from "../../utils/events";

  type Props = {
    onRenderComplete?: () => void;
  };

  let { onRenderComplete }: Props = $props();

  const store = new GroupsStore({ onRenderComplete: () => onRenderComplete?.() });
  setContext(GROUPS_STORE_CONTEXT, store);

  let importRulesModal = $state<{ open: boolean; groupIndex: number | null }>({
    open: false,
    groupIndex: null,
  });

  let importConfigModal = $state<{ open: boolean; fileName: string }>({
    open: false,
    fileName: "",
  });

  let importedGroups = $state<Group[]>([]);
  let isImportingConfig = $state(false);
  let isImportingRules = $state(false);
  let pendingToast = $state<string | null>(null);

  function resetImportConfigModal() {
    importConfigModal = { open: false, fileName: "" };
    importedGroups = [];
  }

  function openImportRulesModal(groupIndex: number) {
    importRulesModal = { open: true, groupIndex };
  }

  function closeImportRulesModal() {
    importRulesModal = { open: false, groupIndex: null };
  }

  function exportConfig() {
    const payload = store.toConfigPayload();
    if (!payload.groups.length) {
      toast.warning(t("Empty config exported"));
    }
    const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "config.mtrickle";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  function importConfig(event: Event) {
    const input = event?.currentTarget as HTMLInputElement;
    const file = input?.files?.[0];
    if (!file) {
      alert(t("Please select a CONFIG file to load."));
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const { groups } = parseConfig(event.target?.result as string);
        if (!groups?.length) {
          toast.error(t("Invalid config file"));
          return;
        }

        importedGroups = groups;
        importConfigModal = {
          open: true,
          fileName: file.name,
        };
      } catch (error) {
        console.error("Error parsing CONFIG:", error);
        toast.error(t("Invalid config file"));
      }
    };
    reader.onerror = (event) => {
      console.error("Error reading file:", event.target?.error);
      toast.error(t("Invalid config file"));
    };

    reader.readAsText(file);
    input.value = "";
  }

  async function handleImportRules(event: CustomEvent<{ group_index: number; rules: Rule[] }>) {
    const { group_index, rules } = event.detail;
    if (!rules.length) return;

    isImportingRules = true;
    await tick();
    try {
      await store.addRulesToGroup(group_index, rules);
      pendingToast = t("Imported rules: " + rules.length);
    } catch (error) {
      console.error("Failed to import rules:", error);
      toast.error(t("Failed to import rules"));
    } finally {
      isImportingRules = false;
    }
  }

  async function handleImportConfig(payload: { groups: Group[]; replace: boolean }) {
    if (!payload.groups.length) return;

    isImportingConfig = true;
    await tick();
    try {
      const cloned = await store.cloneGroupsWithNewIds(payload.groups);
      if (payload.replace) {
        await store.overwriteGroups(cloned);
      } else {
        await store.addGroups(cloned);
      }
      pendingToast = `${t("Config imported")}: ${cloned.length}`;
    } catch (error) {
      console.error("Failed to import config:", error);
      toast.error(t("Failed to import config"));
    } finally {
      isImportingConfig = false;
      resetImportConfigModal();
    }
  }

  $effect(() => {
    const message = pendingToast;
    if (!message) return;
    if (isImportingConfig || isImportingRules) return;
    if (!store.isAllRendered) return;

    let cancelled = false;
    const fire = () => {
      if (cancelled) return;
      if (pendingToast !== message) return;
      toast.success(message);
      pendingToast = null;
    };

    if (typeof requestAnimationFrame === "function") {
      requestAnimationFrame(fire);
    } else {
      setTimeout(fire, 0);
    }

    return () => {
      cancelled = true;
    };
  });

  onMount(() => {
    void store.mount();
  });

  onDestroy(() => {
    store.destroy();
  });
</script>

<div class="groups-page">
  <PageControls
    actionsClass="group-controls-actions"
    controlsClass="group-controls"
    addLabel={t("Add Group")}
    canSave={store.canSave}
    exportLabel={t("Export Config")}
    importLabel={t("Import Config")}
    onAdd={() => store.addGroup()}
    onExport={exportConfig}
    onImport={importConfig}
    onSave={() => store.saveChanges()}
    saveButtonId="save-changes"
    saveLabel={t("Save Changes")}
  >
    {#snippet search()}
      <Search />
    {/snippet}
  </PageControls>

  {#if store.fetchError}
    <Placeholder variant="error" minHeight="auto" subtitle={t("Check connection or try again")}>
      {t("Failed to load groups")}
    </Placeholder>
  {:else if isImportingConfig || isImportingRules || !store.isAllRendered}
    <Placeholder variant="loading" minHeight="auto">
      {t("Loading groups...")}
    </Placeholder>
  {:else if store.noVisibleGroups}
    <Placeholder variant="empty" minHeight="auto">
      {t("No matches found")}
    </Placeholder>
  {:else if store.isEmptyData}
    <Placeholder variant="empty" minHeight="auto" subtitle={t("Create a new group to get started")}>
      {t("No groups yet")}
    </Placeholder>
  {/if}

  <div
    class="group-list"
    class:visible={store.isAllRendered && !isImportingConfig && !isImportingRules}
    style={store.isAllRendered && !isImportingConfig && !isImportingRules ? "" : "display: none;"}
    oninput={store.markDataRevision}
    onchange={store.markDataRevision}
  >
    {#each store.data.slice(0, store.renderGroupsLimit) as group, group_index (group.id)}
      {@const isVisible = !store.searchActive || store.visibilityMap.has(group_index)}

      <div class="group-wrapper" class:is-hidden={!isVisible}>
        {#if group_index === store.firstVisibleGroupIndex}
          <div
            class="group-drop-slot group-drop-slot--top"
            aria-hidden="true"
            use:droppable={{
              data: { group_index, insert: "before" } as GroupDropSlotData,
              scope: "group",
              canDrop: (source: GroupDragData, target: GroupDropSlotData) =>
                source.group_index !== target.group_index,
              dropEffect: "move",
              onDrop: store.handleGroupSlotDrop,
            }}
          ></div>
        {/if}

        <GroupPanel {group_index} on:importRules={() => openImportRulesModal(group_index)} />

        <div
          class="group-drop-slot group-drop-slot--bottom"
          aria-hidden="true"
          use:droppable={{
            data: { group_index, insert: "after" } as GroupDropSlotData,
            scope: "group",
            canDrop: () => true,
            dropEffect: "move",
            onDrop: store.handleGroupSlotDrop,
          }}
        ></div>
      </div>
    {/each}
  </div>
</div>

<ImportRulesDialog
  open={importRulesModal.open}
  group_index={importRulesModal.groupIndex}
  on:close={closeImportRulesModal}
  on:import={handleImportRules}
/>

<ImportConfigDialog
  open={importConfigModal.open}
  groups={importedGroups}
  fileName={importConfigModal.fileName}
  onclose={resetImportConfigModal}
  onimport={handleImportConfig}
/>

<style>
  .group-list {
    min-height: 1px;
    opacity: 0;
  }

  .group-list.visible {
    opacity: 1;
  }

  .group-wrapper {
    position: relative;
    margin: 1rem 0;
  }

  .group-wrapper.is-hidden {
    display: none;
  }

  .group-drop-slot {
    position: absolute;
    left: 0;
    right: 0;
    height: 1rem;
    pointer-events: none;
    background: color-mix(in oklab, var(--accent) 28%, transparent);
    box-shadow: inset 0 0 0 2px color-mix(in oklab, var(--accent) 54%, transparent);
    opacity: 0;
  }

  .group-drop-slot--top {
    top: -1rem;
  }

  .group-drop-slot--bottom {
    bottom: -1rem;
  }

  :global(html[data-dnd-scope="group"]) .group-drop-slot {
    pointer-events: auto;
  }

  :global(html[data-dnd-scope="group"]) .group-drop-slot:global(.dragover) {
    opacity: 1;
  }
</style>
