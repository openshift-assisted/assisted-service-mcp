import importlib
from unittest.mock import MagicMock, patch


def test_update_cluster_vips_and_platform_mapping() -> None:
    """Exercise platform mapping and verify both VIPs in the API update request."""
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
