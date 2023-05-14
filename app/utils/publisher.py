import asyncio
import os

import aio_pika


async def post_code(payload: dict) -> None:
    print(f"Publishing {payload}")
    connection = await aio_pika.connect_robust(
        os.environ["ampquri"],
    )

    async with connection:
        routing_key = "emails"

        channel = await connection.channel()

        await channel.default_exchange.publish(
            aio_pika.Message(body=f"{payload}".encode(), headers={"action": "verify"}),
            routing_key=routing_key,
        )
