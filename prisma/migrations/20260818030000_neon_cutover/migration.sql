-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'RELAY_OPERATOR', 'GATEWAY_OPERATOR', 'CONTENT_PROVIDER', 'STORAGE_PROVIDER', 'COMPUTE_PROVIDER', 'ADMIN');

-- CreateEnum
CREATE TYPE "WaitlistStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'INVITED', 'ACCOUNT_CREATED');

-- CreateEnum
CREATE TYPE "AuditAction" AS ENUM ('LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT', 'SESSION_EXPIRED', 'ACCOUNT_DISABLED', 'ACCOUNT_ENABLED', 'ROLE_CHANGED', 'PASSWORD_RESET', 'WAITLIST_SUBMITTED', 'WAITLIST_APPROVED', 'WAITLIST_REJECTED', 'WAITLIST_INVITED', 'ACCOUNT_CREATED_FROM_WAITLIST', 'DEMO_LOGIN', 'NODE_RECORD_ACCEPTED', 'NODE_RECORD_REJECTED', 'SEQUENCE_FLOOR_UPDATED', 'ARCHITECTURE_TEST_RUN', 'GATEWAY_POLICY_VIOLATION');

-- CreateTable
CREATE TABLE "WaitlistEntry" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "requestedUserType" "Role" NOT NULL DEFAULT 'USER',
    "status" "WaitlistStatus" NOT NULL DEFAULT 'PENDING',
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reviewedAt" TIMESTAMP(3),
    "reviewedById" TEXT,
    "createdUserId" TEXT,

    CONSTRAINT "WaitlistEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "disabled" BOOLEAN NOT NULL DEFAULT false,
    "disabledAt" TIMESTAMP(3),
    "disabledById" TEXT,
    "isDemo" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastActivityAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ip" TEXT,
    "userAgent" TEXT,
    "isDemo" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "action" "AuditAction" NOT NULL,
    "actorUserId" TEXT,
    "targetUserId" TEXT,
    "targetEmail" TEXT,
    "targetNodeId" TEXT,
    "detail" TEXT,
    "ip" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "NodeRecord" (
    "nodeId" TEXT NOT NULL,
    "publicKeyHex" TEXT NOT NULL,
    "capabilities" TEXT NOT NULL,
    "sequence" INTEGER NOT NULL,
    "advertisementHex" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "acceptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NodeRecord_pkey" PRIMARY KEY ("nodeId")
);

-- CreateTable
CREATE TABLE "SequenceFloor" (
    "nodeId" TEXT NOT NULL,
    "currentMaxSequence" INTEGER NOT NULL,
    "lastNonceHex" TEXT,
    "lastAdvancedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SequenceFloor_pkey" PRIMARY KEY ("nodeId")
);

-- CreateTable
CREATE TABLE "DemoAccount" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "userId" TEXT NOT NULL,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DemoAccount_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GatewayPolicy" (
    "id" TEXT NOT NULL,
    "gatewayNodeId" TEXT NOT NULL,
    "perPeerQuota" INTEGER NOT NULL DEFAULT 100,
    "globalQuota" INTEGER NOT NULL DEFAULT 10000,
    "bandwidthBps" INTEGER NOT NULL DEFAULT 1048576,
    "rateLimitPerSec" INTEGER NOT NULL DEFAULT 10,
    "blockPrivateAddresses" BOOLEAN NOT NULL DEFAULT true,
    "blockLoopback" BOOLEAN NOT NULL DEFAULT true,
    "blockLinkLocal" BOOLEAN NOT NULL DEFAULT true,
    "allowedDestinationsJson" TEXT NOT NULL DEFAULT '[]',
    "revokedPeersJson" TEXT NOT NULL DEFAULT '[]',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GatewayPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GatewayPolicyDecision" (
    "id" TEXT NOT NULL,
    "gatewayNodeId" TEXT NOT NULL,
    "peerNodeId" TEXT NOT NULL,
    "destination" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "guard" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GatewayPolicyDecision_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "WaitlistEntry_email_key" ON "WaitlistEntry"("email");

-- CreateIndex
CREATE UNIQUE INDEX "WaitlistEntry_createdUserId_key" ON "WaitlistEntry"("createdUserId");

-- CreateIndex
CREATE INDEX "WaitlistEntry_status_idx" ON "WaitlistEntry"("status");

-- CreateIndex
CREATE INDEX "WaitlistEntry_createdAt_idx" ON "WaitlistEntry"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_role_idx" ON "User"("role");

-- CreateIndex
CREATE INDEX "User_isDemo_idx" ON "User"("isDemo");

-- CreateIndex
CREATE UNIQUE INDEX "Session_token_key" ON "Session"("token");

-- CreateIndex
CREATE INDEX "Session_userId_idx" ON "Session"("userId");

-- CreateIndex
CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");

-- CreateIndex
CREATE INDEX "AuditLog_action_idx" ON "AuditLog"("action");

-- CreateIndex
CREATE INDEX "AuditLog_actorUserId_idx" ON "AuditLog"("actorUserId");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "NodeRecord_publicKeyHex_key" ON "NodeRecord"("publicKeyHex");

-- CreateIndex
CREATE INDEX "NodeRecord_expiresAt_idx" ON "NodeRecord"("expiresAt");

-- CreateIndex
CREATE INDEX "NodeRecord_acceptedAt_idx" ON "NodeRecord"("acceptedAt");

-- CreateIndex
CREATE INDEX "SequenceFloor_lastAdvancedAt_idx" ON "SequenceFloor"("lastAdvancedAt");

-- CreateIndex
CREATE UNIQUE INDEX "DemoAccount_slug_key" ON "DemoAccount"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "DemoAccount_userId_key" ON "DemoAccount"("userId");

-- CreateIndex
CREATE INDEX "GatewayPolicy_gatewayNodeId_idx" ON "GatewayPolicy"("gatewayNodeId");

-- CreateIndex
CREATE INDEX "GatewayPolicyDecision_gatewayNodeId_idx" ON "GatewayPolicyDecision"("gatewayNodeId");

-- CreateIndex
CREATE INDEX "GatewayPolicyDecision_peerNodeId_idx" ON "GatewayPolicyDecision"("peerNodeId");

-- CreateIndex
CREATE INDEX "GatewayPolicyDecision_createdAt_idx" ON "GatewayPolicyDecision"("createdAt");

-- AddForeignKey
ALTER TABLE "WaitlistEntry" ADD CONSTRAINT "WaitlistEntry_reviewedById_fkey" FOREIGN KEY ("reviewedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WaitlistEntry" ADD CONSTRAINT "WaitlistEntry_createdUserId_fkey" FOREIGN KEY ("createdUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_disabledById_fkey" FOREIGN KEY ("disabledById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DemoAccount" ADD CONSTRAINT "DemoAccount_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

