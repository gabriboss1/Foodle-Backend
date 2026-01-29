// Enhanced restaurant description helper
// Provides contextual descriptions based on restaurant name and types

function getRestaurantDescription(name, types) {
    try {
        if (!name || !types) {
            return 'Popular local restaurant';
        }
        
        const restaurantName = name.toLowerCase();
        const typesList = Array.isArray(types) ? types.join(' ').toLowerCase() : '';
        
        // Generate contextual descriptions based on name and types
        let description = '';
        
        // Cuisine-based descriptions
        if (restaurantName.includes('sushi') || typesList.includes('japanese')) {
            description = 'Fresh sushi and authentic Japanese cuisine';
        } else if (restaurantName.includes('pizza') || typesList.includes('italian')) {
            description = 'Authentic Italian dishes and wood-fired pizza';
        } else if (restaurantName.includes('burger') || restaurantName.includes('grill')) {
            description = 'Juicy burgers and American comfort food';
        } else if (typesList.includes('chinese') || restaurantName.includes('chinese')) {
            description = 'Traditional Chinese dishes and dim sum';
        } else if (typesList.includes('mexican') || restaurantName.includes('mexican')) {
            description = 'Authentic Mexican cuisine and fresh ingredients';
        } else if (typesList.includes('thai') || restaurantName.includes('thai')) {
            description = 'Spicy Thai dishes and aromatic curries';
        } else if (typesList.includes('indian') || restaurantName.includes('indian')) {
            description = 'Rich Indian flavors and traditional spices';
        } else if (typesList.includes('french') || restaurantName.includes('french')) {
            description = 'Elegant French cuisine and fine dining';
        } else if (typesList.includes('cafe') || restaurantName.includes('cafe') || restaurantName.includes('coffee')) {
            description = 'Cozy atmosphere with coffee and light meals';
        } else if (typesList.includes('bakery') || restaurantName.includes('bakery')) {
            description = 'Fresh baked goods and artisanal pastries';
        } else if (typesList.includes('bar') || restaurantName.includes('bar')) {
            description = 'Great drinks and bar food in lively atmosphere';
        } else if (typesList.includes('steakhouse') || restaurantName.includes('steak')) {
            description = 'Premium steaks and upscale dining experience';
        } else if (typesList.includes('seafood') || restaurantName.includes('fish')) {
            description = 'Fresh seafood and ocean-to-table dining';
        } else if (typesList.includes('fast_food') || typesList.includes('meal_takeaway')) {
            description = 'Quick service and convenient takeaway options';
        } else if (typesList.includes('restaurant')) {
            description = 'Popular dining spot with diverse menu options';
        } else {
            description = 'Well-reviewed local eatery with quality food';
        }
        
        return description;
        
    } catch (error) {
        console.log(`⚠️ Error generating description for ${name}:`, error.message);
        return 'Popular local restaurant';
    }
}

module.exports = { getRestaurantDescription };
