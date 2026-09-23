## 1. Executive Summary
- **Overall Risk Level**: CRITICAL
- **Target Component**: Order Controller API (`getOrderDetails` & Batch Order Endpoints)
- **Key Findings**: The API contains a direct SQL Injection vulnerability via unparameterized string concatenation (CWE-89), Broken Object Level Authorization (OWASP API1:2023) allowing cross-tenant data exfiltration, and a catastrophic N+1 query loop degrading endpoint performance under concurrent load.

## 2. In-Depth Analysis & Verified Context

### Issue A: Direct SQL Injection in Query Construction
- **Type**: Security
- **Mechanism**: The handler constructs SQL using direct template interpolation (`SELECT * FROM orders WHERE id = '${req.params.id}'`). An attacker supplying a malicious payload (e.g., `' OR '1'='1' --`) can bypass authorization, dump the entire database, or execute destructive DDL commands.
- **Intelligence Citation**: **CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)** and **OWASP Top 10 A03:2021 - Injection**. Prepared statements and parameterized query bindings (`$1`, `$2`) are mandatory.

### Issue B: Broken Object Level Authorization (BOLA / IDOR)
- **Type**: Security
- **Mechanism**: The endpoint extracts `orderId` from URL parameters and fetches the record without checking whether the `order.tenant_id` or `order.user_id` matches the authenticated session context (`req.user.tenantId`). Any authenticated user can read orders belonging to any other user or enterprise tenant simply by altering the ID.
- **Intelligence Citation**: **OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization (BOLA)** & **CWE-639**. Authorization boundaries must be verified directly at the query level.

### Issue C: N+1 Query Loop in Controller
- **Type**: Performance
- **Mechanism**: The handler executes a root query to fetch orders, then iterates over each order in a `for...of` loop executing individual queries to fetch `order_items` and `products`. For 100 orders, this executes 101 separate network roundtrips, causing connection exhaustion and high API response latency.
- **Intelligence Citation**: **Database High Performance Patterns (Anti-pattern: N+1 Queries)**. Batch retrieval with single JOINs or `WHERE order_id = ANY($1)` is required.

## 3. Production Remediation

### Database Migration (SQL)

```sql
-- UP MIGRATION
-- Ensure composite index exists for authorized tenant lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_tenant_id_id 
    ON orders(tenant_id, id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_order_items_order_id_composite 
    ON order_items(order_id, product_id);

-- DOWN MIGRATION
DROP INDEX CONCURRENTLY IF EXISTS idx_order_items_order_id_composite;
DROP INDEX CONCURRENTLY IF EXISTS idx_orders_tenant_id_id;
```

### Backend / API Patch

```typescript
import { Request, Response } from "express";
import { Pool } from "pg";

interface AuthenticatedUser {
  id: string;
  tenantId: string;
  role: string;
}

interface OrderItem {
  id: string;
  productId: string;
  productName: string;
  quantity: number;
  unitPrice: number;
}

interface OrderWithItems {
  id: string;
  userId: string;
  tenantId: string;
  totalAmount: number;
  status: string;
  createdAt: string;
  items: OrderItem[];
}

/**
 * Hardened Order Handler:
 * 1. Eradicates SQL Injection via parameterized query bindings ($1, $2).
 * 2. Mitigates BOLA/IDOR by strictly asserting tenantId from authenticated session.
 * 3. Resolves N+1 query antipattern by performing a single aggregated query with JSON aggregation.
 */
export async function getOrderDetailsHandler(
  req: Request & { user?: AuthenticatedUser },
  res: Response,
  dbPool: Pool
): Promise<Response> {
  try {
    const { orderId } = req.params;
    const sessionUser = req.user;

    // Strict authentication guard
    if (!sessionUser || !sessionUser.tenantId) {
      return res.status(401).json({ error: "Unauthorized: Missing active authentication context" });
    }

    // Input validation: UUID regex to reject malformed parameters early
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(orderId)) {
      return res.status(400).json({ error: "Invalid order identifier format" });
    }

    // Single aggregated query preventing N+1 queries and enforcing tenant boundary
    const query = `
      SELECT 
        o.id,
        o.user_id AS "userId",
        o.tenant_id AS "tenantId",
        o.total_amount AS "totalAmount",
        o.status,
        o.created_at AS "createdAt",
        COALESCE(
          json_agg(
            json_build_object(
              'id', oi.id,
              'productId', oi.product_id,
              'productName', p.name,
              'quantity', oi.quantity,
              'unitPrice', oi.unit_price
            )
          ) FILTER (WHERE oi.id IS NOT NULL),
          '[]'
        ) AS items
      FROM orders o
      LEFT JOIN order_items oi ON oi.order_id = o.id
      LEFT JOIN products p ON p.id = oi.product_id
      WHERE o.id = $1 AND o.tenant_id = $2
      GROUP BY o.id;
    `;

    const result = await dbPool.query(query, [orderId, sessionUser.tenantId]);

    if (result.rows.length === 0) {
      // Return 404 to avoid leaking existence of foreign tenant orders
      return res.status(404).json({ error: "Order not found" });
    }

    const orderData: OrderWithItems = result.rows[0];
    return res.status(200).json({ data: orderData });
  } catch (error) {
    // Log internally without leaking raw SQL stack traces to client
    console.error("[OrderController] Internal Error:", error);
    return res.status(500).json({ error: "An unexpected error occurred while processing the request" });
  }
}
```

## 4. Verification & Impact Metrics

- **Query / Algorithm Complexity**:
  - Before: 1 query for order + N queries for items = **O(N)** network roundtrips.
  - After: Single aggregated SQL query with hash join and grouped JSON aggregation = **O(1)** network roundtrip.
- **Security Posture**:
  - **CWE-89 (SQL Injection)**: Eliminated. Parameters are strictly passed through Postgres prepared protocol.
  - **OWASP API1:2023 (BOLA)**: Mitigated. Query hard-enforces `tenant_id = $2` from the verified user token.
- **Deployment Notes**:
  - Zero application downtime required.
  - Non-blocking index creation `CREATE INDEX CONCURRENTLY` ensures database stays responsive during migration.
