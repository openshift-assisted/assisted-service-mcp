import importlib
from unittest.mock import patch, MagicMock


def test_get_host_overrides_scheme_and_netloc() -> None:
    sc_mod = importlib.import_module(
        "assisted_service_mcp.src.service_client.assisted_service_api"
    )
    configs = sc_mod.Configuration()
    configs.host = "http://placeholder.local"

    with (
        patch(
            "assisted_service_mcp.src.service_client.assisted_service_api.get_setting",
            side_effect=lambda k: (
                "https://real.example.com" if k == "INVENTORY_URL" else ""
            ),
        ),
        patch.object(sc_mod, "Configuration", return_value=configs),
    ):
        client = sc_mod.InventoryClient("token")
        # ensure inventory_url set from patched get_setting
        client.inventory_url = "https://real.example.com"
        host = client._get_host(configs)  # pylint: disable=protected-access
        assert host.startswith("https://real.example.com")


def test_update_cluster_vips_and_platform_mapping() -> None:
    sc_mod = importlib.import_module(
        "assisted_service_mcp.src.service_client.assisted_service_api"
    )
    client = sc_mod.InventoryClient("token")

    with (
        patch.object(client, "_installer_api") as mock_api,
        patch(
            "assisted_service_mcp.src.service_client.assisted_service_api.Helpers.get_platform_model",
            return_value="platform_model",
        ),
    ):
        api_instance = MagicMock()
        mock_api.return_value = api_instance
        api_instance.v2_update_cluster = MagicMock()

        async def run() -> None:
            await client.update_cluster(
                cluster_id="cid",
                api_vip="1.2.3.4",
                ingress_vip="5.6.7.8",
                platform={"type": "vsphere"},
            )

        import asyncio

        asyncio.run(run())

        # Ensure vips were set and API called
        called_kwargs = api_instance.v2_update_cluster.call_args.kwargs
        params = called_kwargs["cluster_update_params"]
        assert params.api_vips and params.api_vips[0].ip == "1.2.3.4"
        assert params.ingress_vips and params.ingress_vips[0].ip == "5.6.7.8"
