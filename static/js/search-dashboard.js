const containerProcessListDT = new simpleDatatables.DataTable("#container-process-list", {
    searchable: true,
    sortable: true,
    fixedHeight: true,
    perPage: 10,   
    footer: false,       
    labels: {
        placeholder: "Search...",
        perPage: "{select} entries per page",
        noRows: "No entries found",
        info: "Showing {start} to {end} of {rows} entries"
    },
    layout: {
        top: "{select}{search}",
        bottom: "{info}{pager}"
    }
});

const containerNetworkConnectionsDT = new simpleDatatables.DataTable("#container-network-connections", {
    searchable: true,
    sortable: true,
    fixedHeight: true,
    perPage: 10,   
    footer: false,       
    labels: {
        placeholder: "Search...",
        perPage: "{select} entries per page",
        noRows: "No entries found",
        info: "Showing {start} to {end} of {rows} entries"
    },
    layout: {
        top: "{select}{search}",
        bottom: "{info}{pager}"
    }
});

const containerImageHistoryDT = new simpleDatatables.DataTable("#container-image-history", {
    searchable: true,
    sortable: true,
    fixedHeight: true,
    perPage: 10,   
    footer: false,       
    labels: {
        placeholder: "Search...",
        perPage: "{select} entries per page",
        noRows: "No entries found",
        info: "Showing {start} to {end} of {rows} entries"
    },
    layout: {
        top: "{select}{search}",
        bottom: "{info}{pager}"
    }
});

