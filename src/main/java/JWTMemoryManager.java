import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Memory management utilities for the JWT extension
 * Handles proper cleanup of crypto objects, temporary data, and resource management
 */
public class JWTMemoryManager {
    private static final JWTLogger logger = JWTLogger.getLogger(JWTMemoryManager.class);
    
    // Singleton instance with thread-safe initialization
    private static final AtomicReference<JWTMemoryManager> instance = new AtomicReference<>();
    
    // Thread-safe collections for tracking resources
    private final ConcurrentHashMap<String, WeakReference<Object>> managedObjects = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Runnable> cleanupTasks = new ConcurrentHashMap<>();
    
    // Scheduled executor for periodic cleanup
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "JWT-MemoryManager-Cleanup");
        t.setDaemon(true);
        return t;
    });
    
    private volatile ScheduledFuture<?> cleanupTask;
    private volatile boolean shutdown = false;
    
    // Statistics
    private volatile long totalObjectsManaged = 0;
    private volatile long totalCleanupOperations = 0;
    private volatile long lastCleanupTime = 0;
    
    private JWTMemoryManager() {
        startPeriodicCleanup();
        registerShutdownHook();
        logger.info("JWT Memory Manager initialized");
    }
    
    /**
     * Get the singleton instance (thread-safe)
     */
    public static JWTMemoryManager getInstance() {
        JWTMemoryManager current = instance.get();
        if (current == null) {
            synchronized (JWTMemoryManager.class) {
                current = instance.get();
                if (current == null) {
                    current = new JWTMemoryManager();
                    instance.set(current);
                }
            }
        }
        return current;
    }
    
    /**
     * Register an object for memory management
     */
    public <T> T register(String id, T object) {
        if (shutdown) {
            logger.warn("Attempted to register object after shutdown: %s", id);
            return object;
        }
        
        if (object == null) {
            logger.warn("Attempted to register null object with id: %s", id);
            return null;
        }
        
        managedObjects.put(id, new WeakReference<>(object));
        totalObjectsManaged++;
        
        logger.trace("Registered object for management: %s (type: %s)", id, object.getClass().getSimpleName());
        return object;
    }
    
    /**
     * Register an object with a custom cleanup task
     */
    public <T> T register(String id, T object, Runnable cleanupTask) {
        register(id, object);
        if (cleanupTask != null) {
            cleanupTasks.put(id, cleanupTask);
            logger.trace("Registered cleanup task for object: %s", id);
        }
        return object;
    }
    
    /**
     * Manually cleanup a specific object
     */
    public void cleanup(String id) {
        if (id == null) return;
        
        WeakReference<Object> ref = managedObjects.remove(id);
        Runnable cleanupTask = cleanupTasks.remove(id);
        
        if (cleanupTask != null) {
            try {
                cleanupTask.run();
                logger.trace("Executed cleanup task for: %s", id);
            } catch (Exception e) {
                logger.error("Error executing cleanup task for %s: %s", id, e.getMessage());
            }
        }
        
        if (ref != null) {
            Object obj = ref.get();
            if (obj != null) {
                performAutoCleanup(obj);
            }
            totalCleanupOperations++;
        }
    }
    
    /**
     * Create a secure byte array that will be automatically zeroed when cleaned up
     */
    public byte[] createSecureByteArray(String id, int size) {
        byte[] array = new byte[size];
        return register(id, array, () -> {
            // Zero out the array for security
            for (int i = 0; i < array.length; i++) {
                array[i] = 0;
            }
            logger.trace("Zeroed secure byte array: %s", id);
        });
    }
    
    /**
     * Create a temporary string that will be cleared from memory
     */
    public StringBuilder createTemporaryString(String id) {
        StringBuilder sb = new StringBuilder();
        return register(id, sb, () -> {
            // Clear the string builder
            sb.setLength(0);
            sb.trimToSize();
            logger.trace("Cleared temporary string: %s", id);
        });
    }
    
    /**
     * Perform automatic cleanup based on object type
     */
    private void performAutoCleanup(Object obj) {
        try {
            if (obj instanceof StringBuilder) {
                StringBuilder sb = (StringBuilder) obj;
                sb.setLength(0);
                sb.trimToSize();
            } else if (obj instanceof byte[]) {
                byte[] array = (byte[]) obj;
                for (int i = 0; i < array.length; i++) {
                    array[i] = 0;
                }
            } else if (obj instanceof Map) {
                ((Map<?, ?>) obj).clear();
            }
            
            logger.trace("Performed auto-cleanup for object type: %s", obj.getClass().getSimpleName());
        } catch (Exception e) {
            logger.error("Error during auto-cleanup: %s", e.getMessage());
        }
    }
    
    /**
     * Start periodic cleanup of garbage collected objects
     */
    private void startPeriodicCleanup() {
        cleanupTask = cleanupExecutor.scheduleWithFixedDelay(
            this::performPeriodicCleanup,
            30, // Initial delay
            60, // Period
            TimeUnit.SECONDS
        );
        logger.debug("Started periodic cleanup task (every 60 seconds)");
    }
    
    /**
     * Perform periodic cleanup of weak references and execute cleanup tasks
     */
    private void performPeriodicCleanup() {
        if (shutdown) return;
        
        long startTime = System.currentTimeMillis();
        int removedCount = 0;
        
        try {
            // Clean up garbage collected objects
            for (Map.Entry<String, WeakReference<Object>> entry : managedObjects.entrySet()) {
                WeakReference<Object> ref = entry.getValue();
                if (ref.get() == null) {
                    // Object was garbage collected, run cleanup task if present
                    Runnable cleanupTask = cleanupTasks.remove(entry.getKey());
                    if (cleanupTask != null) {
                        try {
                            cleanupTask.run();
                        } catch (Exception e) {
                            logger.error("Error in cleanup task for %s: %s", entry.getKey(), e.getMessage());
                        }
                    }
                    managedObjects.remove(entry.getKey());
                    removedCount++;
                    totalCleanupOperations++;
                }
            }
            
            // Suggest garbage collection if we cleaned up many objects
            if (removedCount > 10) {
                System.gc();
                logger.debug("Suggested garbage collection after cleaning %d objects", removedCount);
            }
            
            lastCleanupTime = System.currentTimeMillis();
            long duration = lastCleanupTime - startTime;
            
            if (removedCount > 0 || logger.isDebugEnabled()) {
                logger.debug("Periodic cleanup completed: removed %d objects in %d ms (total managed: %d)", 
                           removedCount, duration, managedObjects.size());
            }
            
        } catch (Exception e) {
            logger.error("Error during periodic cleanup: %s", e.getMessage());
        }
    }
    
    /**
     * Force immediate cleanup of all managed objects
     */
    public void forceCleanup() {
        logger.info("Force cleanup initiated - cleaning %d managed objects", managedObjects.size());
        
        // Execute all cleanup tasks
        for (Map.Entry<String, Runnable> entry : cleanupTasks.entrySet()) {
            try {
                entry.getValue().run();
                logger.trace("Executed cleanup task: %s", entry.getKey());
            } catch (Exception e) {
                logger.error("Error in force cleanup task %s: %s", entry.getKey(), e.getMessage());
            }
        }
        
        // Perform auto cleanup for remaining objects
        for (Map.Entry<String, WeakReference<Object>> entry : managedObjects.entrySet()) {
            Object obj = entry.getValue().get();
            if (obj != null) {
                performAutoCleanup(obj);
            }
        }
        
        cleanupTasks.clear();
        managedObjects.clear();
        
        // Force garbage collection
        System.gc();
        
        logger.info("Force cleanup completed");
    }
    
    /**
     * Get memory management statistics
     */
    public MemoryStats getStats() {
        return new MemoryStats(
            managedObjects.size(),
            cleanupTasks.size(),
            totalObjectsManaged,
            totalCleanupOperations,
            lastCleanupTime
        );
    }
    
    /**
     * Register shutdown hook for proper cleanup
     */
    private void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown hook triggered - performing final cleanup");
            shutdown();
        }, "JWT-MemoryManager-Shutdown"));
    }
    
    /**
     * Shutdown the memory manager
     */
    public void shutdown() {
        if (shutdown) return;
        
        shutdown = true;
        logger.info("Shutting down JWT Memory Manager");
        
        // Cancel periodic cleanup
        if (cleanupTask != null) {
            cleanupTask.cancel(false);
        }
        
        // Force final cleanup
        forceCleanup();
        
        // Shutdown executor
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        logger.info("JWT Memory Manager shutdown completed");
    }
    
    /**
     * Memory management statistics
     */
    public static class MemoryStats {
        public final int currentManagedObjects;
        public final int currentCleanupTasks;
        public final long totalObjectsManaged;
        public final long totalCleanupOperations;
        public final long lastCleanupTime;
        
        MemoryStats(int currentManagedObjects, int currentCleanupTasks, 
                   long totalObjectsManaged, long totalCleanupOperations, long lastCleanupTime) {
            this.currentManagedObjects = currentManagedObjects;
            this.currentCleanupTasks = currentCleanupTasks;
            this.totalObjectsManaged = totalObjectsManaged;
            this.totalCleanupOperations = totalCleanupOperations;
            this.lastCleanupTime = lastCleanupTime;
        }
        
        @Override
        public String toString() {
            return String.format("MemoryStats{managed=%d, tasks=%d, total=%d, cleanups=%d, lastCleanup=%d}",
                currentManagedObjects, currentCleanupTasks, totalObjectsManaged, 
                totalCleanupOperations, lastCleanupTime);
        }
    }
}
