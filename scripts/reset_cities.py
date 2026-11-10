import asyncio
import asyncpg
import re

async def reset_cities():
    with open('db/init.sql', 'r', encoding='utf-8') as f:
        content = f.read()

    c_match = re.search(r'INSERT INTO cities.*?;', content, re.DOTALL)
    conn = await asyncpg.connect('postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev')
    await conn.execute('TRUNCATE cities CASCADE;')
    await conn.execute("ALTER SEQUENCE cities_id_seq RESTART WITH 1;")
    if c_match:
        await conn.execute(c_match.group(0))
        print('Cities re-inserted starting from 1.')

    min_id = await conn.fetchval('SELECT MIN(id) FROM cities;')
    max_id = await conn.fetchval('SELECT MAX(id) FROM cities;')
    print(f'Cities range: {min_id}..{max_id}')
    await conn.close()

if __name__ == '__main__':
    asyncio.run(reset_cities())

