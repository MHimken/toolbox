# Broken Autopilot Device Cleanup Flow

<!-- markdownlint-disable MD033 -->

<div id="mermaid-zoom-toolbar" style="display:inline-flex;gap:4px;align-items:center;background:#fff;border:1px solid #ccc;border-radius:4px;padding:4px 8px;margin-bottom:8px;box-shadow:0 1px 4px rgba(0,0,0,.2);font-family:sans-serif;font-size:14px;">
  <button id="mermaid-zoom-out" title="Zoom out">&minus;</button>
  <span id="mermaid-zoom-level">100%</span>
  <button id="mermaid-zoom-in" title="Zoom in">+</button>
  <button id="mermaid-zoom-reset" title="Reset zoom">Reset</button>
</div>
<div id="mermaid-zoom-container" style="overflow:auto;border:1px solid #e0e0e0;border-radius:4px;">

```mermaid
flowchart LR
    classDef input fill:#e8f0fe,stroke:#4a6fa5,color:#17324d
    classDef decision fill:#fff4d6,stroke:#b7791f,color:#4a3410
    classDef action fill:#dff7e3,stroke:#2f855a,color:#1f3b2d
    classDef result fill:#f3e8ff,stroke:#7c3aed,color:#35143f

    subgraph AP["Autopilot Object"]
        direction TB
        ap_start([Device serial loaded]):::input
        ap_csv{Serial in CSV?}:::decision
        ap_remove[AutopilotWhatIf = Remove]:::action
        ap_retain[AutopilotWhatIf = Retain]:::result
    end

    subgraph EID_AP["Entra Object (from AP)"]
        direction TB
        eid_ap_found{Entra device found?}:::decision
        eid_ap_delete{Approx. last sign-in <= deletion threshold?}:::decision
        eid_ap_disable{Approx. last sign-in <= disable threshold?}:::decision
        eid_ap_remove[Entra action = Remove]:::action
        eid_ap_disable_action[Entra action = Disable]:::action
        eid_ap_retain[Entra action = Retain]:::result
    end

    subgraph INTUNE["Intune Object"]
        direction TB
        intune_found{Intune device found?}:::decision
        intune_delete{Last sync <= deletion threshold?}:::decision
        intune_disable{Last sync <= disable threshold?}:::decision
        intune_remove[Intune action = Remove]:::action
        intune_retire[Intune action = Retire]:::action
        intune_retain[Intune action = Retain]:::result
        intune_not_found[Intune action = Not Found]:::result
    end

    subgraph EID_INTUNE["Entra Object (from Intune)"]
        direction TB
        eid_intune_link{Intune linked to same Entra object?}:::decision
        eid_intune_delete{Approx. last sign-in <= deletion threshold?}:::decision
        eid_intune_disable{Approx. last sign-in <= disable threshold?}:::decision
        eid_intune_remove[Entra action = Remove]:::action
        eid_intune_disable_action[Entra action = Disable]:::action
        eid_intune_retain[Entra action = Retain]:::result
        eid_intune_na[Entra action = Not Applicable]:::result
    end

    ap_start --> ap_csv
    ap_csv -- Yes --> ap_remove
    ap_csv -- No --> ap_retain
    ap_remove --> eid_ap_found
    ap_retain --> eid_ap_found

    eid_ap_found -- No --> eid_ap_retain
    eid_ap_found -- Yes --> eid_ap_delete
    eid_ap_delete -- Yes --> eid_ap_remove
    eid_ap_delete -- No --> eid_ap_disable
    eid_ap_disable -- Yes --> eid_ap_disable_action
    eid_ap_disable -- No --> eid_ap_retain

    ap_retain --> intune_found
    ap_remove --> intune_found
    eid_ap_retain --> intune_found
    eid_ap_disable_action --> intune_found
    eid_ap_remove --> intune_found

    intune_found -- No --> intune_not_found
    intune_found -- Yes --> intune_delete
    intune_delete -- Yes --> intune_remove
    intune_delete -- No --> intune_disable
    intune_disable -- Yes --> intune_retire
    intune_disable -- No --> intune_retain

    intune_found -- No --> eid_intune_na
    intune_found -- Yes --> eid_intune_link
    eid_intune_link -- No --> eid_intune_na
    eid_intune_link -- Yes --> eid_intune_delete
    eid_intune_delete -- Yes --> eid_intune_remove
    eid_intune_delete -- No --> eid_intune_disable
    eid_intune_disable -- Yes --> eid_intune_disable_action
    eid_intune_disable -- No --> eid_intune_retain

    ap_remove -. explicit cleanup candidate .-> ap_csv
    intune_remove -. delete or retire decision .-> eid_intune_link
    intune_retire -. retire path .-> eid_intune_link
```

</div>

<script>
(function () {
  var zoomLevel = 1;
  var minZoom = 0.2;
  var maxZoom = 3;
  var step = 0.1;
  var svgEl = null;
  var baseWidth = null;
  var baseHeight = null;

  function applyZoom() {
    if (!svgEl) { return; }
    svgEl.style.width = (baseWidth * zoomLevel) + 'px';
    svgEl.style.height = (baseHeight * zoomLevel) + 'px';
    document.getElementById('mermaid-zoom-level').textContent = Math.round(zoomLevel * 100) + '%';
  }

  function init() {
    svgEl = document.querySelector('#mermaid-zoom-container svg');
    if (!svgEl) {
      // mermaid renders asynchronously, so retry until the SVG exists
      setTimeout(init, 200);
      return;
    }
    var rect = svgEl.getBoundingClientRect();
    baseWidth = rect.width;
    baseHeight = rect.height;
    applyZoom();
  }

  document.getElementById('mermaid-zoom-in').addEventListener('click', function () {
    zoomLevel = Math.min(maxZoom, zoomLevel + step);
    applyZoom();
  });
  document.getElementById('mermaid-zoom-out').addEventListener('click', function () {
    zoomLevel = Math.max(minZoom, zoomLevel - step);
    applyZoom();
  });
  document.getElementById('mermaid-zoom-reset').addEventListener('click', function () {
    zoomLevel = 1;
    applyZoom();
  });

  init();
})();
</script>

<!-- markdownlint-enable MD033 -->

The flow mirrors the script's current evaluation order:

- Autopilot uses the CSV flag when present.
- Entra from Autopilot uses the same deletion and disable thresholds as the other objects.
- Intune uses last sync thresholds to choose Remove, Retire, or Retain.
- Entra from Intune follows the same date thresholds when Intune is present, otherwise it stays Not Applicable.
