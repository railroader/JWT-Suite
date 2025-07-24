import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Thread-safe resource tracker for JWT extension operations
 * Manages lifecycle of crypto operations, temporary data, and system resources
 */
public class JWTResourceTracker {
    private static final Map<String, ResourceInfo> activeResources = new ConcurrentHashMap<>();
    private static final AtomicInteger resourceCounter = new AtomicInteger(0);
    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    
    private static class ResourceInfo {
        final String id;
        final String type;
        final long createdAt;
        final Thread ownerThread;
        volatile boolean released;
        
        ResourceInfo(String id, String type) {
            this.id = id;
            this.type = type;
            this.createdAt = System.currentTimeMillis();
            this.ownerThread = Thread.currentThread();
            this.released = false;
        }
    }
    
    /**
     * Track a new resource and return unique identifier
     */
    public static String trackResource(String type) {
        String resourceId = "jwt-resource-" + resourceCounter.incrementAndGet();
        ResourceInfo info = new ResourceInfo(resourceId, type);
        
        lock.writeLock().lock();
        try {
            activeResources.put(resourceId, info);
            System.out.println("[ResourceTracker] Tracking " + type + " resource: " + resourceId);
        } finally {
            lock.writeLock().unlock();
        }
        
        return resourceId;
    }
    
    /**
     * Release a tracked resource
     */
    public static void releaseResource(String resourceId) {
        if (resourceId == null) return;
        
        lock.writeLock().lock();
        try {
            ResourceInfo info = activeResources.remove(resourceId);
            if (info != null) {
                info.released = true;
                System.out.println("[ResourceTracker] Released " + info.type + " resource: " + resourceId);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Get statistics about tracked resources
     */
    public static String getResourceStats() {
        lock.readLock().lock();
        try {
            Map<String, Integer> typeCounts = new ConcurrentHashMap<>();
            for (ResourceInfo info : activeResources.values()) {
                typeCounts.merge(info.type, 1, Integer::sum);
            }
            
            StringBuilder stats = new StringBuilder("Active Resources: ");
            stats.append("Total=").append(activeResources.size());
            for (Map.Entry<String, Integer> entry : typeCounts.entrySet()) {
                stats.append(", ").append(entry.getKey()).append("=").append(entry.getValue());
            }
            
            return stats.toString();
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Clean up resources older than specified age
     */
    public static int cleanupOldResources(long maxAgeMs) {
        lock.writeLock().lock();
        try {
            long cutoff = System.currentTimeMillis() - maxAgeMs;
            List<String> toRemove = new ArrayList<>();
            
            for (Map.Entry<String, ResourceInfo> entry : activeResources.entrySet()) {
                if (entry.getValue().createdAt < cutoff) {
                    toRemove.add(entry.getKey());
                }
            }
            
            for (String id : toRemove) {
                ResourceInfo info = activeResources.remove(id);
                System.out.println("[ResourceTracker] Cleaned up stale " + info.type + " resource: " + id);
            }
            
            return toRemove.size();
        } finally {
            lock.writeLock().unlock();
        }
    }
}
