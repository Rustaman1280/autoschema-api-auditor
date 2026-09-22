/**
 * Order Controller (Legacy Implementation)
 * WARNING: Contains intentional SQL Injection, BOLA/IDOR, and N+1 query patterns.
 */

import { Request, Response } from "express";
import { db } from "../database";

export async function getOrderDetails(req: Request, res: Response) {
  try {
    const orderId = req.params.id;

    // VULNERABILITY 1: Direct SQL Injection (CWE-89)
    // String interpolation without parameterized query bindings
    const orderQuery = `SELECT * FROM orders WHERE id = '${orderId}'`;
    const orderResult = await db.query(orderQuery);

    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }

    const order = orderResult.rows[0];

    // VULNERABILITY 2: Broken Object Level Authorization (BOLA/IDOR - OWASP API1:2023)
    // No verification that order.tenant_id matches req.user.tenantId or order.user_id matches req.user.id

    // PERFORMANCE BOTTLENECK: N+1 Query Antipattern
    // Fetching items inside a loop instead of batching or joining
    const itemsResult = await db.query(`SELECT * FROM order_items WHERE order_id = '${order.id}'`);
    const items = [];

    for (const item of itemsResult.rows) {
      // Multiple queries executed inside iteration
      const productResult = await db.query(`SELECT name, sku FROM products WHERE id = '${item.product_id}'`);
      items.push({
        ...item,
        product: productResult.rows[0]
      });
    }

    return res.json({
      order: {
        ...order,
        items
      }
    });
  } catch (err: any) {
    // Leaking internal database error traces to external clients
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
}
