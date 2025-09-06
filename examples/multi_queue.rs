use libublk::ctrl::UblkCtrlBuilder;
use libublk::io::{UblkDev, UblkQueue};
use libublk::multi_queue::MultiQueueManager;
use libublk::UblkFlags;

/// Example demonstrating multi-queue resource registration
///
/// This example shows how to:
/// 1. Create multiple queues using MultiQueueManager
/// 2. Accumulate file and buffer resources across queues
/// 3. Register all resources in a single batch operation
/// 4. Use index translation for queue-specific operations
fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("Multi-Queue Resource Registration Example");
    println!("=========================================");

    let nr_queues = 4;
    // Create a ublk controller with multiple queues for demonstration
    let ctrl = UblkCtrlBuilder::default()
        .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
        .name("multi-queue-demo")
        .nr_queues(nr_queues)
        .build()?;

    println!("Created ublk control device: {}", ctrl.get_name());

    // Initialize the target implementation
    let tgt_init = |dev: &mut UblkDev| {
        println!("Initializing multi-queue target...");

        // Create a multi-queue manager
        let mut manager = MultiQueueManager::new();
        let mut queues = Vec::new();

        // Create multiple queues with automatic resource management
        for q_id in 0..nr_queues {
            println!(
                "Creating queue {} with automatic resource registration",
                q_id
            );

            // Create queue - this will automatically add its resources to the manager
            let queue = UblkQueue::new_multi(q_id, dev, &mut manager)?;

            println!(
                "  Queue {} created with slab key: {}",
                q_id,
                queue.get_slab_key()
            );

            // Check if queue has resource range (for multi-queue scenarios)
            if let Some(range) = queue.get_resource_range() {
                println!(
                    "  Resource range - Files: {}..{}, Buffers: {}..{}",
                    range.file_start_index,
                    range.file_start_index + range.file_count,
                    range.buffer_start_index,
                    range.buffer_start_index + range.buffer_count
                );
            }

            queues.push(queue);
        }

        println!(
            "All queues created. Total managed queues: {}",
            manager.queue_count()
        );

        // Register all accumulated resources in one batch operation
        println!("Registering all queue resources with io_uring...");
        manager.register_resources()?;
        println!("✓ Resource registration completed successfully!");

        // Demonstrate index translation
        if let Some(queue) = queues.first() {
            println!("\nIndex translation examples for queue 0:");
            println!(
                "  Local file index 0 -> Global index {}",
                queue.translate_file_index(0)
            );
            if queue
                .get_resource_range()
                .map(|r| r.buffer_count > 0)
                .unwrap_or(false)
            {
                println!(
                    "  Local buffer index 0 -> Global index {}",
                    queue.translate_buffer_index(0)
                );
            }
        }

        println!("\n✓ Multi-queue setup completed successfully!");
        println!("  - {} queues created", queues.len());
        println!("  - Resources registered in single batch operation");
        println!("  - Ready for I/O operations");

        Ok(())
    };

    // Create the ublk device with our multi-queue initialization
    let _dev = UblkDev::new(ctrl.get_name(), tgt_init, &ctrl)?;

    println!("\n🎉 Multi-queue demo completed successfully!");
    println!("The multi-queue resource registration system is working correctly.");

    Ok(())
}
