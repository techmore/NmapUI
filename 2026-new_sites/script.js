/ Mobile Menu Toggle
const mobileMenuBtn = document.getElementById('mobile-menu-btn');
const mobileMenu = document.getElementById('mobile-menu');

if (mobileMenuBtn && mobileMenu) {
    mobileMenuBtn.addEventListener('click', () => {
        mobileMenu.classList.toggle('hidden');
    });

    mobileMenu.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', () => {
            mobileMenu.classList.add('hidden');
        });
    });
}

// Global Search Functionality
const searchInput = document.getElementById('global-search');

if (searchInput) {
    // Real-time search across all content
    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase().trim();
        
        // Search in all compact cards
        document.querySelectorAll('.compact-card').forEach(card => {
            const title = card.querySelector('h3')?.textContent.toLowerCase() || '';
            const subtitle = card.querySelector('p')?.textContent.toLowerCase() || '';
            const meta = card.textContent.toLowerCase() || '';
            
            if (!searchTerm || title.includes(searchTerm) || subtitle.includes(searchTerm) || meta.includes(searchTerm)) {
                card.style.display = '';
                setTimeout(() => {
                    card.style.opacity = '1';
                }, 10);
            } else {
                card.style.opacity = '0';
                setTimeout(() => {
                    card.style.display = 'none';
                }, 150);
            }
        });
    });

    // Keyboard shortcut Cmd/Ctrl + K
    document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
        }
        
        if (e.key === 'Escape') {
            const mobileMenu = document.getElementById('mobile-menu');
            if (mobileMenu) mobileMenu.classList.add('hidden');
            searchInput.blur();
        }
    });
}

// Filter Pills Functionality
const filterPills = document.querySelectorAll('.filter-pill');

filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
        // Remove active from siblings
        const parent = pill.parentElement;
        if (parent) {
            parent.querySelectorAll('.filter-pill').forEach(p => {
                p.classList.remove('active', 'bg-olive-600', 'text-white');
                p.classList.add('text-stone-600');
                if (!p.classList.contains('bg-white') && !p.classList.contains('border')) {
                    p.classList.add('text-stone-600');
                }
            });
        }
        
        // Add active to clicked
        pill.classList.add('active');
        pill.classList.remove('text-stone-600');
        
        // If it's a sidebar filter with icon
        if (pill.querySelector('svg')) {
            pill.classList.add('bg-olive-600', 'text-white');
        }
        
        const filter = pill.getAttribute('data-filter');
        if (filter && filter !== 'all') {
            // Filter logic - show/hide based on data attribute or content type
            document.querySelectorAll('.compact-card').forEach(card => {
                // Check if card has matching category or related content
                const cardText = card.textContent.toLowerCase();
                let matches = false;
                
                if (filter === 'books' && (cardText.includes('book') || cardText.includes('press') || cardText.includes('pp'))) matches = true;
                else if (filter === 'video' && (cardText.includes('video') || cardText.includes('movie') || cardText.includes('hbo') || cardText.includes('bbc') || cardText.includes('eps') || cardText.includes('m'))) matches = true;
                else if (filter === 'research' && (cardText.includes('pdf') || cardText.includes('paper') || cardText.includes('journal') || cardText.includes('et al') || cardText.includes('cites'))) matches = true;
                else if (filter === 'audio' && (cardText.includes('audio') || cardText.includes('podcast') || cardText.includes('headphones') || cardText.includes('h'))) matches = true;
                else if (filter === 'photos' && (cardText.includes('photo') || cardText.includes('collection') || cardText.includes('natgeo'))) matches = true;
                
                if (matches || filter === 'all') {
                    card.style.display = '';
                    setTimeout(() => card.style.opacity = '1', 10);
                } else {
                    card.style.opacity = '0';
                    setTimeout(() => card.style.display = 'none', 200);
                }
            });
        } else if (filter === 'all') {
            document.querySelectorAll('.compact-card').forEach(card => {
                card.style.display = '';
                setTimeout(() => card.style.opacity = '1', 10);
            });
        }
    });
});

// Horizontal scroll buttons
window.scrollContent = function(gridId, direction) {
    const grid = document.getElementById(gridId + '-grid');
    if (grid) {
        const scrollAmount = 300;
        grid.scrollBy({ left: direction * scrollAmount, behavior: 'smooth' });
    }
};

// Compact card interactions
document.querySelectorAll('.compact-card').forEach(card => {
    card.addEventListener('click', () => {
        // In real app: open detail view
        card.style.transform = 'scale(0.98)';
        setTimeout(() => {
            card.style.transform = '';
        }, 150);
    });
});

// Add to collection buttons
document.querySelectorAll('.compact-card button').forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const icon = btn.querySelector('svg');
        const isAdded = btn.classList.contains('bg-olive-600');
        
        if (!isAdded) {
            btn.classList.add('bg-olive-600', 'text-white');
            btn.classList.remove('bg-white');
            btn.innerHTML = '<i data-lucide="check" class="w-4 h-4"></i>';
        } else {
            btn.classList.remove('bg-olive-600', 'text-white');
            btn.classList.add('bg-white');
            btn.innerHTML = '<i data-lucide="plus" class="w-4 h-4 text-olive-700"></i>';
        }
        
        lucide.createIcons();
        
        // Visual feedback
        btn.style.transform = 'scale(1.2)';
        setTimeout(() => {
            btn.style.transform = '';
        }, 200);
    });
});

// Lazy loading images with blur effect
if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.classList.add('opacity-0');
                setTimeout(() => {
                    img.classList.remove('opacity-0');
                    img.classList.add('transition-opacity', 'duration-500');
                }, 50);
                imageObserver.unobserve(img);
            }
        });
    }, { rootMargin: '50px' });

    document.querySelectorAll('img').forEach(img => {
        imageObserver.observe(img);
    });
}

// Load more functionality
const loadMoreBtn = document.querySelector('button:not([onclick])');
if (loadMoreBtn && loadMoreBtn.textContent.includes('Load More')) {
    loadMoreBtn.addEventListener('click', function() {
        const originalText = this.textContent;
        this.innerHTML = '<span class="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></span> Loading...';
        this.disabled = true;
        
        setTimeout(() => {
            this.textContent = originalText;
            this.disabled = false;
            // In real app: append new content
        }, 800);
    });
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
});
